// NetWatch για macOS — εικονίδιο στη γραμμή μενού + παράθυρο με τον πίνακα ελέγχου.
// Ξεκινά το Python backend (netwatch.py) και δείχνει το UI του σε WKWebView.
// Build: ./macapp/build.sh
import AppKit
import WebKit

enum Mode: String { case live, demo, pcap }

let support = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
    .appendingPathComponent("NetWatch")
let appDir = support.appendingPathComponent("app")
let venvPython = support.appendingPathComponent("venv/bin/python")
let logFile = support.appendingPathComponent("netwatch.log")
let portFile = support.appendingPathComponent("port")

func sh(_ s: String) -> String { "'" + s.replacingOccurrences(of: "'", with: "'\\''") + "'" }

// ---------------- Backend ----------------
final class Backend {
    var mode: Mode = .demo
    var pcap: String?
    var port: Int?
    var child: Process?
    var onReady: ((Int) -> Void)?
    var onFail: ((String) -> Void)?
    var onStatus: ((String) -> Void)?

    var base: URL? { port.map { URL(string: "http://127.0.0.1:\($0)")! } }

    /// Αντιγράφει τα αρχεία του NetWatch στο Application Support (εκεί μένουν και τα δεδομένα)
    /// και φτιάχνει το Python περιβάλλον την πρώτη φορά.
    func prepare() throws {
        try FileManager.default.createDirectory(at: support, withIntermediateDirectories: true)
        guard let res = Bundle.main.resourceURL?.appendingPathComponent("netwatch") else { return }
        try run("/usr/bin/rsync", ["-a", "--delete", "--exclude", "data/", "--exclude", "config.yaml",
                                   "--exclude", "rules/local.yaml", "--exclude", "__pycache__/",
                                   res.path + "/", appDir.path + "/"])
        if !FileManager.default.isExecutableFile(atPath: venvPython.path) {
            onStatus?("Πρώτη εκκίνηση: εγκαθιστώ το Python περιβάλλον (scapy, pyyaml)…")
            try run("/usr/bin/python3", ["-m", "venv", support.appendingPathComponent("venv").path])
            try run(venvPython.path, ["-m", "pip", "install", "-q", "-r", appDir.appendingPathComponent("requirements.txt").path])
        }
    }

    @discardableResult
    func run(_ exe: String, _ args: [String]) throws -> Int32 {
        let p = Process()
        p.executableURL = URL(fileURLWithPath: exe)
        p.arguments = args
        p.standardOutput = FileHandle.nullDevice
        p.standardError = FileHandle(forWritingAtPath: logFile.path) ?? FileHandle.nullDevice
        try p.run()
        p.waitUntilExit()
        if p.terminationStatus != 0 {
            throw NSError(domain: "NetWatch", code: Int(p.terminationStatus),
                          userInfo: [NSLocalizedDescriptionKey: "\(URL(fileURLWithPath: exe).lastPathComponent) απέτυχε (δες \(logFile.path))"])
        }
        return p.terminationStatus
    }

    func start(_ mode: Mode, pcap: String? = nil) {
        self.mode = mode
        self.pcap = pcap
        port = nil
        try? FileManager.default.removeItem(at: portFile)
        FileManager.default.createFile(atPath: logFile.path, contents: nil)
        DispatchQueue.global().async {
            do {
                try self.prepare()
            } catch {
                DispatchQueue.main.async { self.onFail?(error.localizedDescription) }
                return
            }
            var args = [appDir.appendingPathComponent("netwatch.py").path, "--no-open",
                        "--port-file", portFile.path, "--parent-pid", String(getpid())]
            switch mode {
            case .demo: args.append("--demo")
            case .pcap: args += ["--pcap", pcap ?? "", "--loop"]
            case .live: break
            }
            DispatchQueue.main.async { self.onStatus?(mode == .live ? "Ζητώ κωδικό διαχειριστή για καταγραφή πακέτων…" : "Ξεκινά το NetWatch…") }
            if mode == .live {
                // Η καταγραφή πακέτων θέλει root: το macOS ρωτά τον κωδικό στο δικό του παράθυρο.
                let env = "SUDO_USER=\(sh(NSUserName())) SUDO_UID=\(getuid()) SUDO_GID=\(getgid())"
                let cmd = "cd \(sh(appDir.path)) && \(env) \(sh(venvPython.path)) " + args.map(sh).joined(separator: " ")
                    + " >> \(sh(logFile.path)) 2>&1 &"
                let script = "do shell script \"\(cmd.replacingOccurrences(of: "\\", with: "\\\\").replacingOccurrences(of: "\"", with: "\\\""))\" with administrator privileges with prompt \"Το NetWatch χρειάζεται δικαιώματα διαχειριστή για να «ακούει» την κίνηση του δικτύου.\""
                var err: NSDictionary?
                var ok = false
                DispatchQueue.main.sync { ok = NSAppleScript(source: script)?.executeAndReturnError(&err) != nil }
                if !ok {
                    DispatchQueue.main.async { self.onFail?("Δεν δόθηκαν δικαιώματα διαχειριστή — ξεκίνα σε Demo ή άνοιξε ένα pcap.") }
                    return
                }
            } else {
                let p = Process()
                p.executableURL = venvPython
                p.arguments = args
                p.currentDirectoryURL = appDir
                let fh = FileHandle(forWritingAtPath: logFile.path)
                fh?.seekToEndOfFile()
                p.standardOutput = fh
                p.standardError = fh
                do { try p.run() } catch {
                    DispatchQueue.main.async { self.onFail?(error.localizedDescription) }
                    return
                }
                self.child = p
            }
            for _ in 0..<300 {  // έως 60 δευτ. (η πρώτη φόρτωση του scapy είναι αργή)
                if let s = try? String(contentsOf: portFile, encoding: .utf8), let p = Int(s.trimmingCharacters(in: .whitespacesAndNewlines)) {
                    DispatchQueue.main.async { self.port = p; self.onReady?(p) }
                    return
                }
                if let c = self.child, !c.isRunning { break }
                Thread.sleep(forTimeInterval: 0.2)
            }
            let tail = (try? String(contentsOf: logFile, encoding: .utf8))?.split(separator: "\n").suffix(3).joined(separator: "\n") ?? ""
            DispatchQueue.main.async { self.onFail?("Το NetWatch δεν ξεκίνησε.\n\(tail)") }
        }
    }

    func post(_ path: String, _ body: [String: Any] = [:], done: ((Data?) -> Void)? = nil) {
        guard let u = base?.appendingPathComponent(path) else { return }
        var r = URLRequest(url: u)
        r.httpMethod = "POST"
        r.setValue("application/json", forHTTPHeaderField: "Content-Type")
        r.httpBody = try? JSONSerialization.data(withJSONObject: body)
        r.timeoutInterval = 3
        URLSession.shared.dataTask(with: r) { d, _, _ in done?(d) }.resume()
    }

    /// Σταματά το backend (και το root, μέσω του /api/shutdown).
    func stop(wait: Bool = false) {
        let sem = DispatchSemaphore(value: 0)
        if port != nil { post("api/shutdown") { _ in sem.signal() } } else { sem.signal() }
        if wait { _ = sem.wait(timeout: .now() + 1.5) }
        child?.terminate()
        child = nil
        port = nil
    }
}

// ---------------- Παράθυρο ----------------
final class WebController: NSObject, WKNavigationDelegate, WKUIDelegate, WKDownloadDelegate {
    let web: WKWebView
    let window: NSWindow

    override init() {
        let cfg = WKWebViewConfiguration()
        cfg.websiteDataStore = .default()  // κρατά localStorage (κουίζ, CTF)
        web = WKWebView(frame: .zero, configuration: cfg)
        window = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 1400, height: 880),
                          styleMask: [.titled, .closable, .miniaturizable, .resizable, .fullSizeContentView],
                          backing: .buffered, defer: false)
        super.init()
        web.navigationDelegate = self
        web.uiDelegate = self
        web.setValue(false, forKey: "drawsBackground")
        window.title = "NetWatch"
        window.titlebarAppearsTransparent = true
        window.backgroundColor = NSColor(red: 0.02, green: 0.04, blue: 0.08, alpha: 1)
        window.contentView = web
        window.minSize = NSSize(width: 900, height: 560)
        window.isReleasedWhenClosed = false
        window.center()
        window.setFrameAutosaveName("NetWatchMain")
        message("Ξεκινά το NetWatch…")
    }

    func message(_ text: String, error: Bool = false) {
        let esc = text.replacingOccurrences(of: "&", with: "&amp;").replacingOccurrences(of: "<", with: "&lt;")
            .replacingOccurrences(of: "\n", with: "<br>")
        web.loadHTMLString("""
        <html><body style="margin:0;height:100vh;display:flex;align-items:center;justify-content:center;background:#050a14;color:#cfe0f5;font:14px -apple-system,sans-serif;text-align:center">
        <div><div style="font-size:42px;margin-bottom:12px">\(error ? "⚠️" : "🛰")</div>
        <div style="color:\(error ? "#ff8da0" : "#cfe0f5");max-width:560px;line-height:1.5">\(esc)</div>
        \(error ? "" : "<div style=\"margin-top:14px;color:#6d7f99;font-size:12px\">NetWatch</div>")</div></body></html>
        """, baseURL: nil)
    }

    func load(_ url: URL) { web.load(URLRequest(url: url)) }

    // εξωτερικοί σύνδεσμοι (MITRE, Shodan…) → στον browser
    func webView(_ w: WKWebView, createWebViewWith c: WKWebViewConfiguration, for a: WKNavigationAction,
                 windowFeatures f: WKWindowFeatures) -> WKWebView? {
        if let u = a.request.url { NSWorkspace.shared.open(u) }
        return nil
    }

    func webView(_ w: WKWebView, decidePolicyFor a: WKNavigationAction,
                 decisionHandler: @escaping (WKNavigationActionPolicy) -> Void) {
        if a.shouldPerformDownload { return decisionHandler(.download) }
        if let u = a.request.url, let h = u.host, !["127.0.0.1", "localhost"].contains(h), a.navigationType == .linkActivated {
            NSWorkspace.shared.open(u)
            return decisionHandler(.cancel)
        }
        decisionHandler(.allow)
    }

    func webView(_ w: WKWebView, navigationAction: WKNavigationAction, didBecome d: WKDownload) { d.delegate = self }
    func webView(_ w: WKWebView, navigationResponse: WKNavigationResponse, didBecome d: WKDownload) { d.delegate = self }

    // αναφορές JSON / εικόνες χάρτη → Λήψεις
    func download(_ d: WKDownload, decideDestinationUsing r: URLResponse, suggestedFilename name: String,
                  completionHandler: @escaping (URL?) -> Void) {
        let dir = FileManager.default.urls(for: .downloadsDirectory, in: .userDomainMask)[0]
        var url = dir.appendingPathComponent(name)
        let stem = url.deletingPathExtension().lastPathComponent, ext = url.pathExtension
        var i = 1
        while FileManager.default.fileExists(atPath: url.path) {
            url = dir.appendingPathComponent("\(stem) \(i)").appendingPathExtension(ext)
            i += 1
        }
        completionHandler(url)
    }

    func downloadDidFinish(_ d: WKDownload) {
        if let u = d.progress.fileURL { NSWorkspace.shared.activateFileViewerSelecting([u]) }
    }

    func webView(_ w: WKWebView, runJavaScriptAlertPanelWithMessage m: String, initiatedByFrame f: WKFrameInfo,
                 completionHandler: @escaping () -> Void) {
        let a = NSAlert()
        a.messageText = m
        a.beginSheetModal(for: window) { _ in completionHandler() }
    }

    func webView(_ w: WKWebView, runJavaScriptConfirmPanelWithMessage m: String, initiatedByFrame f: WKFrameInfo,
                 completionHandler: @escaping (Bool) -> Void) {
        let a = NSAlert()
        a.messageText = m
        a.addButton(withTitle: "OK")
        a.addButton(withTitle: "Άκυρο")
        a.beginSheetModal(for: window) { completionHandler($0 == .alertFirstButtonReturn) }
    }
}

// ---------------- Εφαρμογή ----------------
final class AppDelegate: NSObject, NSApplicationDelegate, NSWindowDelegate, NSMenuDelegate {
    let backend = Backend()
    var web: WebController!
    var item: NSStatusItem!
    var timer: Timer?
    var status: [String: Any] = [:]
    var lastAlertId = 0

    func applicationDidFinishLaunching(_ n: Notification) {
        buildMainMenu()
        web = WebController()
        web.window.delegate = self
        item = NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength)
        let menu = NSMenu()
        menu.delegate = self
        item.menu = menu
        setIcon(level: "idle", count: 0)

        backend.onStatus = { [weak self] s in self?.web.message(s) }
        backend.onReady = { [weak self] port in
            self?.web.load(URL(string: "http://127.0.0.1:\(port)")!)
            self?.poll()
        }
        backend.onFail = { [weak self] s in
            self?.web.message(s, error: true)
            self?.setIcon(level: "idle", count: 0)
            self?.showWindow()
        }
        timer = Timer.scheduledTimer(withTimeInterval: 3, repeats: true) { [weak self] _ in self?.poll() }

        let saved = Mode(rawValue: UserDefaults.standard.string(forKey: "mode") ?? "") ?? .demo
        let pcap = UserDefaults.standard.string(forKey: "pcap")
        if saved == .pcap, let p = pcap, FileManager.default.fileExists(atPath: p) {
            backend.start(.pcap, pcap: p)
        } else {
            backend.start(saved == .pcap ? .demo : saved)
        }
        showWindow()
    }

    func applicationWillTerminate(_ n: Notification) { backend.stop(wait: true) }
    func applicationShouldHandleReopen(_ s: NSApplication, hasVisibleWindows f: Bool) -> Bool { showWindow(); return true }

    // ορατό στο Dock μόνο όσο είναι ανοιχτό το παράθυρο· μετά ζει στη γραμμή μενού
    func windowWillClose(_ n: Notification) { NSApp.setActivationPolicy(.accessory) }

    @objc func showWindow() {
        NSApp.setActivationPolicy(.regular)
        web.window.makeKeyAndOrderFront(nil)
        NSApp.activate(ignoringOtherApps: true)
    }

    func switchMode(_ m: Mode, pcap: String? = nil) {
        UserDefaults.standard.set(m.rawValue, forKey: "mode")
        if let p = pcap { UserDefaults.standard.set(p, forKey: "pcap") }
        backend.stop(wait: true)
        status = [:]
        lastAlertId = 0
        web.message("Αλλαγή λειτουργίας…")
        showWindow()
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.5) { self.backend.start(m, pcap: pcap) }
    }

    @objc func goLive() { switchMode(.live) }
    @objc func goDemo() { switchMode(.demo) }
    @objc func openPcap() {
        let p = NSOpenPanel()
        p.allowedContentTypes = []
        p.allowsOtherFileTypes = true
        p.message = "Διάλεξε αρχείο .pcap ή .pcapng"
        p.directoryURL = appDir.appendingPathComponent("samples")
        NSApp.activate(ignoringOtherApps: true)
        if p.runModal() == .OK, let u = p.url { switchMode(.pcap, pcap: u.path) }
    }
    @objc func wifiCheck() { backend.post("api/wifi") { _ in DispatchQueue.main.async { self.poll() } } }
    @objc func openInBrowser() { if let b = backend.base { NSWorkspace.shared.open(b) } }
    @objc func openData() { NSWorkspace.shared.open(support) }
    @objc func openLog() { NSWorkspace.shared.open(logFile) }
    @objc func quit() { NSApp.terminate(nil) }

    func poll() {
        guard let b = backend.base else { return }
        URLSession.shared.dataTask(with: b.appendingPathComponent("api/status")) { d, _, _ in
            guard let d = d, let j = try? JSONSerialization.jsonObject(with: d) as? [String: Any] else { return }
            DispatchQueue.main.async { self.update(j) }
        }.resume()
    }

    func update(_ j: [String: Any]) {
        status = j
        let high = j["high"] as? Int ?? 0, med = j["med"] as? Int ?? 0, total = j["alerts"] as? Int ?? 0
        let wifi = j["wifi"] as? [String: Any]
        var level = high > 0 ? "bad" : med > 0 ? "warn" : "ok"
        if let wl = wifi?["level"] as? String, wl == "bad" || (wl == "warn" && level == "ok") { level = wl }
        setIcon(level: level, count: total)
        if let last = j["last"] as? [String: Any], let id = last["id"] as? Int { lastAlertId = max(lastAlertId, id) }
    }

    func setIcon(level: String, count: Int) {
        guard let b = item.button else { return }
        let (name, color): (String, NSColor) = {
            switch level {
            case "bad": return ("exclamationmark.shield.fill", .systemRed)
            case "warn": return ("shield.lefthalf.filled", .systemYellow)
            case "ok": return ("checkmark.shield.fill", .systemGreen)
            default: return ("shield", .secondaryLabelColor)
            }
        }()
        let conf = NSImage.SymbolConfiguration(pointSize: 14, weight: .medium)
            .applying(NSImage.SymbolConfiguration(paletteColors: [color]))
        let img = NSImage(systemSymbolName: name, accessibilityDescription: "NetWatch")?.withSymbolConfiguration(conf)
        img?.isTemplate = level == "idle"
        b.image = img
        b.imagePosition = .imageLeading
        b.title = count > 0 ? " \(count)" : ""
        b.toolTip = "NetWatch"
    }

    // το μενού χτίζεται κάθε φορά που ανοίγει, με τα τελευταία στοιχεία
    func menuNeedsUpdate(_ menu: NSMenu) {
        menu.removeAllItems()
        func info(_ t: String) { let i = NSMenuItem(title: t, action: nil, keyEquivalent: ""); i.isEnabled = false; menu.addItem(i) }
        func add(_ t: String, _ a: Selector, _ k: String = "", on: Bool = false) {
            let i = NSMenuItem(title: t, action: a, keyEquivalent: k)
            i.target = self
            i.state = on ? .on : .off
            menu.addItem(i)
        }
        let modeName = ["live": "● LIVE", "demo": "DEMO", "pcap": "▶ PCAP"][backend.mode.rawValue] ?? ""
        if backend.port == nil {
            info("NetWatch — ξεκινά… (\(modeName))")
        } else {
            let iface = status["iface"] as? String ?? ""
            info("NetWatch — \(modeName) · \(iface)")
            let n = status["alerts"] as? Int ?? 0
            info(n == 0 ? "Καμία ειδοποίηση" : "⚠ \(n) ειδοποιήσεις (υψηλές: \(status["high"] as? Int ?? 0))")
            if let l = status["last"] as? [String: Any] {
                info("   τελευταία: \(l["type"] as? String ?? "") — \(l["actor"] as? String ?? "")")
            }
            if let w = status["wifi"] as? [String: Any] {
                let icon = ["ok": "✅", "warn": "⚠️", "bad": "❌"][w["level"] as? String ?? ""] ?? ""
                info("☕ \(w["ssid"] as? String ?? "Wi‑Fi"): \(icon) \(w["verdict"] as? String ?? "") (\(w["score"] as? Int ?? 0)/100)")
            }
        }
        menu.addItem(.separator())
        add("Άνοιγμα NetWatch", #selector(showWindow), "o")
        add((status["wifi_running"] as? Bool ?? false) ? "☕ Έλεγχος Wi‑Fi… (τρέχει)" : "☕ Έλεγχος Wi‑Fi τώρα", #selector(wifiCheck))
        menu.addItem(.separator())
        add("Live — πραγματική κίνηση (κωδικός διαχειριστή)", #selector(goLive), on: backend.mode == .live)
        add("Demo — προσομοίωση", #selector(goDemo), on: backend.mode == .demo)
        add("Αναπαραγωγή pcap…", #selector(openPcap), on: backend.mode == .pcap)
        menu.addItem(.separator())
        add("Άνοιγμα στον browser", #selector(openInBrowser))
        add("Φάκελος δεδομένων", #selector(openData))
        add("Αρχείο καταγραφής", #selector(openLog))
        menu.addItem(.separator())
        add("Έξοδος", #selector(quit), "q")
    }

    func buildMainMenu() {
        let main = NSMenu()
        let appItem = NSMenuItem()
        main.addItem(appItem)
        let am = NSMenu()
        am.addItem(withTitle: "Σχετικά με το NetWatch", action: #selector(NSApplication.orderFrontStandardAboutPanel(_:)), keyEquivalent: "")
        am.addItem(.separator())
        am.addItem(withTitle: "Απόκρυψη", action: #selector(NSApplication.hide(_:)), keyEquivalent: "h")
        am.addItem(withTitle: "Έξοδος", action: #selector(NSApplication.terminate(_:)), keyEquivalent: "q")
        appItem.submenu = am
        let editItem = NSMenuItem()
        main.addItem(editItem)
        let em = NSMenu(title: "Επεξεργασία")  // για ⌘C / ⌘V / ⌘A μέσα στο παράθυρο (κανόνες, CTF)
        em.addItem(withTitle: "Αναίρεση", action: Selector(("undo:")), keyEquivalent: "z")
        em.addItem(withTitle: "Επανάληψη", action: Selector(("redo:")), keyEquivalent: "Z")
        em.addItem(.separator())
        em.addItem(withTitle: "Αποκοπή", action: #selector(NSText.cut(_:)), keyEquivalent: "x")
        em.addItem(withTitle: "Αντιγραφή", action: #selector(NSText.copy(_:)), keyEquivalent: "c")
        em.addItem(withTitle: "Επικόλληση", action: #selector(NSText.paste(_:)), keyEquivalent: "v")
        em.addItem(withTitle: "Επιλογή όλων", action: #selector(NSText.selectAll(_:)), keyEquivalent: "a")
        editItem.submenu = em
        let winItem = NSMenuItem()
        main.addItem(winItem)
        let wm = NSMenu(title: "Παράθυρο")
        wm.addItem(withTitle: "Ελαχιστοποίηση", action: #selector(NSWindow.miniaturize(_:)), keyEquivalent: "m")
        wm.addItem(withTitle: "Κλείσιμο", action: #selector(NSWindow.performClose(_:)), keyEquivalent: "w")
        wm.addItem(withTitle: "Επαναφόρτωση", action: #selector(WKWebView.reload(_:)), keyEquivalent: "r")
        winItem.submenu = wm
        NSApp.mainMenu = main
    }
}

let app = NSApplication.shared
let delegate = AppDelegate()
app.delegate = delegate
app.setActivationPolicy(.regular)
app.run()
