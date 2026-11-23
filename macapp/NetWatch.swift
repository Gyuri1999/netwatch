// NetWatch για macOS — εικονίδιο στη γραμμή μενού + παράθυρο με τον πίνακα ελέγχου.
// Ξεκινά το Python backend (netwatch.py) και δείχνει το UI του σε WKWebView.
// Build: ./macapp/build.sh
import AppKit
import ServiceManagement
import SwiftUI
import WebKit
import UserNotifications

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
                // Μόνο η python πάει στο παρασκήνιο, με ΟΛΑ τα fd της αλλού: αλλιώς το «do shell script»
                // περιμένει για πάντα να κλείσει η έξοδος και η εφαρμογή «κολλάει».
                // Πρώτα σκοτώνουμε τυχόν παλιά backend (root) που έμειναν από προηγούμενη εκκίνηση που δεν έκλεισε
                // με ⌘Q — αλλιώς μένουν «zombies» που πιάνουν τη θύρα και δείχνουν 0 πακέτα.
                // ΠΡΟΣΟΧΗ: ταιριάζουμε ΜΟΝΟ τη διεργασία python (ο διερμηνέας έχει «MacOS/Python» στο cmdline),
                // ΟΧΙ το shell/osascript που ξεκινά την εντολή (αυτά αναφέρουν «venv/bin/python» και θα αυτοσκοτώνονταν).
                let kill = "pkill -f '[M]acOS/Python.*netwatch[.]py' 2>/dev/null; sleep 0.5; "
                let cmd = kill + "cd \(sh(appDir.path)) || exit 1; \(env) \(sh(venvPython.path)) " + args.map(sh).joined(separator: " ")
                    + " </dev/null >>\(sh(logFile.path)) 2>&1 &"
                let script = "do shell script \"\(cmd.replacingOccurrences(of: "\\", with: "\\\\").replacingOccurrences(of: "\"", with: "\\\""))\" with administrator privileges with prompt \"Το NetWatch χρειάζεται δικαιώματα διαχειριστή για να «ακούει» την κίνηση του δικτύου.\""
                // osascript σε ξεχωριστή διεργασία: το παράθυρο κωδικού δεν «παγώνει» ποτέ την εφαρμογή
                let osa = Process()
                osa.executableURL = URL(fileURLWithPath: "/usr/bin/osascript")
                osa.arguments = ["-e", script]
                osa.standardOutput = FileHandle.nullDevice
                osa.standardError = FileHandle.nullDevice
                var ok = false
                if (try? osa.run()) != nil {
                    osa.waitUntilExit()
                    ok = osa.terminationStatus == 0
                }
                if !ok {
                    DispatchQueue.main.async { self.onFail?("Δεν δόθηκαν δικαιώματα διαχειριστή — ξεκίνα σε Demo ή άνοιξε ένα pcap.") }
                    return
                }
            } else {
                // καθάρισμα παλιών backend (demo/pcap τρέχουν ως χρήστης) πριν ξεκινήσουμε νέο
                let pk = Process()
                pk.executableURL = URL(fileURLWithPath: "/usr/bin/pkill")
                pk.arguments = ["-f", appDir.appendingPathComponent("netwatch.py").path]
                try? pk.run(); pk.waitUntilExit()
                Thread.sleep(forTimeInterval: 0.4)
                let p = Process()
                p.executableURL = venvPython
                p.arguments = args
                p.currentDirectoryURL = appDir
                p.environment = ProcessInfo.processInfo.environment.merging(["NETWATCH_HOST_APP": "1"]) { $1 }
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
        cfg.userContentController.addUserScript(WKUserScript(source: "window.__nwErr=[];addEventListener('error',e=>__nwErr.push(String(e.message)+' @'+(e.filename||'')+':'+(e.lineno||'')));addEventListener('unhandledrejection',e=>__nwErr.push('rej '+String(e.reason)))", injectionTime: .atDocumentStart, forMainFrameOnly: true))
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

    // Η διεύθυνση που ΠΡΕΠΕΙ να δείχνει το παράθυρο. Αν η φόρτωση αποτύχει (backend δεν απαντά ακόμα,
    // WebKit process πέθανε μετά από sleep/restart), ξαναδοκιμάζουμε — αλλιώς έμενε για πάντα στο splash.
    var target: URL?
    var tries = 0

    func trace(_ s: String) {
        let f = support.appendingPathComponent("app.log")
        if !FileManager.default.fileExists(atPath: f.path) { FileManager.default.createFile(atPath: f.path, contents: nil) }
        guard let fh = FileHandle(forWritingAtPath: f.path) else { return }
        fh.seekToEndOfFile(); fh.write("[app] \(s)\n".data(using: .utf8)!); try? fh.close()
    }

    func message(_ text: String, error: Bool = false) {
        target = nil
        let esc = text.replacingOccurrences(of: "&", with: "&amp;").replacingOccurrences(of: "<", with: "&lt;")
            .replacingOccurrences(of: "\n", with: "<br>")
        web.loadHTMLString("""
        <html><body style="margin:0;height:100vh;display:flex;align-items:center;justify-content:center;background:#050a14;color:#cfe0f5;font:14px -apple-system,sans-serif;text-align:center">
        <div><div style="font-size:42px;margin-bottom:12px">\(error ? "⚠️" : "🛰")</div>
        <div style="color:\(error ? "#ff8da0" : "#cfe0f5");max-width:560px;line-height:1.5">\(esc)</div>
        \(error ? "" : "<div style=\"margin-top:14px;color:#6d7f99;font-size:12px\">NetWatch</div>")</div></body></html>
        """, baseURL: nil)
    }

    func load(_ url: URL) {
        target = url; tries = 0
        trace("φόρτωση \(url)")
        web.load(URLRequest(url: url, cachePolicy: .reloadIgnoringLocalCacheData, timeoutInterval: 10))
        watchdog()
    }

    private func retry(_ why: String) {
        guard let u = target, tries < 40 else { return }
        tries += 1
        trace("ξαναδοκιμή \(tries) (\(why))")
        DispatchQueue.main.asyncAfter(deadline: .now() + 1) { [weak self] in
            guard let self = self, self.target == u else { return }
            self.web.load(URLRequest(url: u, cachePolicy: .reloadIgnoringLocalCacheData, timeoutInterval: 10))
        }
    }

    /// Κάθε 3″: αν πρέπει να δείχνουμε το UI αλλά το παράθυρο είναι ακόμα στο splash (about:blank) → ξαναφόρτωσε.
    private func watchdog() {
        DispatchQueue.main.asyncAfter(deadline: .now() + 3) { [weak self] in
            guard let self = self, let u = self.target else { return }
            if self.web.url?.host != u.host || self.web.url?.port != u.port {
                if !self.web.isLoading || self.tries == 0 { self.retry("ακόμα στο splash") }
            }
            if self.tries < 40 { self.watchdog() }
        }
    }

    func webView(_ w: WKWebView, didFailProvisionalNavigation n: WKNavigation!, withError e: Error) {
        if (e as NSError).code != NSURLErrorCancelled { retry(e.localizedDescription) }
    }
    func webView(_ w: WKWebView, didFail n: WKNavigation!, withError e: Error) {
        if (e as NSError).code != NSURLErrorCancelled { retry(e.localizedDescription) }
    }
    func webViewWebContentProcessDidTerminate(_ w: WKWebView) {
        trace("το WebKit process τερματίστηκε")
        if let u = target { tries = 0; web.load(URLRequest(url: u)) }
    }
    func webView(_ w: WKWebView, didFinish n: WKNavigation!) {
        if let t = target, let u = w.url, u.host == t.host { trace("το UI φόρτωσε (δοκιμές: \(tries))"); tries = 40
            DispatchQueue.main.asyncAfter(deadline: .now() + 6) { [weak self] in
                let js = "JSON.stringify({u:location.href,t:(document.body&&document.body.innerText||'').slice(0,300),e:window.__nwErr||[],sw:!!(navigator.serviceWorker&&navigator.serviceWorker.controller)})"
                self?.web.evaluateJavaScript(js) { r, e in self?.trace("κατάσταση: \(r ?? e?.localizedDescription ?? "-")") }
            }
        }
    }

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

    // αρχεία με «Content-Disposition: attachment» (PDF/PNG/SVG/draw.io/Markdown, αναφορές) → κατέβασμα στις Λήψεις,
    // όχι άνοιγμα μέσα στο παράθυρο (αλλιώς το PDF «γεμίζει» την οθόνη χωρίς κουμπί επιστροφής).
    func webView(_ w: WKWebView, decidePolicyFor r: WKNavigationResponse,
                 decisionHandler: @escaping (WKNavigationResponsePolicy) -> Void) {
        if let resp = r.response as? HTTPURLResponse,
           let cd = resp.value(forHTTPHeaderField: "Content-Disposition"),
           cd.lowercased().contains("attachment") {
            return decisionHandler(.download)
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
final class AppDelegate: NSObject, NSApplicationDelegate, NSWindowDelegate, NSMenuDelegate, UNUserNotificationCenterDelegate {
    let backend = Backend()
    var web: WebController!
    var item: NSStatusItem!
    var timer: Timer?
    var status: [String: Any] = [:]
    var lastAlertId = 0
    var lastNotifId = -1   // -1 = δεν έχουμε βάση ακόμη· δεν ειδοποιούμε για όσα υπήρχαν ήδη στην εκκίνηση
    var rates: [(t: Double, pkts: Double, bytes: Double, pps: Double, bps: Double)] = []

    // Native ειδοποιήσεις (δικό μας εικονίδιο + κουμπιά «Άνοιξε» / «Σίγασε»)
    func setupNotifications() {
        let c = UNUserNotificationCenter.current()
        c.delegate = self
        let open = UNNotificationAction(identifier: "open", title: "Άνοιξε", options: [.foreground])
        let mute = UNNotificationAction(identifier: "mute", title: "Σίγασε 1 ώρα", options: [])
        c.setNotificationCategories([UNNotificationCategory(identifier: "nw.alert", actions: [open, mute],
                                                            intentIdentifiers: [], options: [])])
        c.requestAuthorization(options: [.alert, .sound]) { _, _ in }
    }

    func postAlertNotification(_ a: [String: Any]) {
        let sev = a["sev"] as? String ?? "high"
        let ic = sev == "high" ? "🔴" : sev == "med" ? "🟠" : "🟡"
        let n = UNMutableNotificationContent()
        n.title = "\(ic) NetWatch"
        n.subtitle = a["type"] as? String ?? "Ειδοποίηση"
        n.body = String((a["detail"] as? String ?? "").prefix(220))
        n.sound = .default
        n.categoryIdentifier = "nw.alert"
        n.userInfo = ["type": a["type"] as? String ?? "", "actor": a["actor"] as? String ?? ""]
        let req = UNNotificationRequest(identifier: "nw-\(a["id"] as? Int ?? 0)", content: n, trigger: nil)
        UNUserNotificationCenter.current().add(req)
    }

    func userNotificationCenter(_ c: UNUserNotificationCenter, willPresent n: UNNotification,
                                withCompletionHandler h: @escaping (UNNotificationPresentationOptions) -> Void) {
        h([.banner, .sound])
    }

    func userNotificationCenter(_ c: UNUserNotificationCenter, didReceive r: UNNotificationResponse,
                                withCompletionHandler h: @escaping () -> Void) {
        let info = r.notification.request.content.userInfo
        if r.actionIdentifier == "mute", let t = info["type"] as? String, !t.isEmpty {
            backend.post("api/alerts/mute", ["type": t, "actor": info["actor"] as? String ?? "",
                                             "minutes": 60, "note": "Από την ειδοποίηση"]) { _ in
                DispatchQueue.main.async { self.poll() }
            }
        } else {
            DispatchQueue.main.async { self.showWindow(); self.runJS("setView('page');showTab('alerts')", orLoad: "tab=alerts") }
        }
        h()
    }

    func applicationDidFinishLaunching(_ n: Notification) {
        buildMainMenu()
        setupNotifications()
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
        rates = []
        UserDefaults.standard.set(m.rawValue, forKey: "mode")
        if let p = pcap { UserDefaults.standard.set(p, forKey: "pcap") }
        backend.stop(wait: true)
        status = [:]
        lastAlertId = 0
        lastNotifId = -1
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

    /// Ο πίνακας (κουμπί «🟢 Πέρασε σε Live τώρα») γράφει mode-request.json — για όταν το εικονίδιο
    /// της γραμμής μενού κρύβεται (π.χ. πίσω από την εγκοπή της οθόνης).
    func checkModeRequest() {
        let f = support.appendingPathComponent("mode-request.json")
        guard let d = try? Data(contentsOf: f) else { return }
        try? FileManager.default.removeItem(at: f)
        guard let j = try? JSONSerialization.jsonObject(with: d) as? [String: Any],
              let m = j["mode"] as? String, let t = j["t"] as? Double,
              Date().timeIntervalSince1970 - t < 60 else { return }
        if m.hasPrefix("live"), backend.mode != .live { switchMode(.live) }
        else if m == "demo", backend.mode != .demo { switchMode(.demo) }
    }

    func poll() {
        checkModeRequest()
        guard let b = backend.base else { return }
        URLSession.shared.dataTask(with: b.appendingPathComponent("api/status")) { d, _, _ in
            guard let d = d, let j = try? JSONSerialization.jsonObject(with: d) as? [String: Any] else { return }
            DispatchQueue.main.async { self.update(j) }
        }.resume()
    }

    func update(_ j: [String: Any]) {
        status = j
        let now = Date().timeIntervalSince1970, p = Double(j["pkts"] as? Int ?? 0), by = Double(j["bytes"] as? Int ?? 0)
        if let l = rates.last, now > l.t, p >= l.pkts {
            rates.append((now, p, by, (p - l.pkts) / (now - l.t), max(0, by - l.bytes) / (now - l.t)))
        } else {
            rates = [(now, p, by, 0, 0)]
        }
        if rates.count > 40 { rates.removeFirst(rates.count - 40) }
        let high = j["high"] as? Int ?? 0, med = j["med"] as? Int ?? 0, total = j["alerts"] as? Int ?? 0
        let wifi = j["wifi"] as? [String: Any]
        var level = high > 0 ? "bad" : med > 0 ? "warn" : "ok"
        if let wl = wifi?["level"] as? String, wl == "bad" || (wl == "warn" && level == "ok") { level = wl }
        setIcon(level: level, count: total)
        if let last = j["last"] as? [String: Any], let id = last["id"] as? Int {
            if lastNotifId < 0 {
                lastNotifId = id                              // βάση στην εκκίνηση — χωρίς ειδοποίηση για το ιστορικό
            } else if id > lastNotifId {
                lastNotifId = id
                if (last["sev"] as? String) == "high" { postAlertNotification(last) }
            }
            lastAlertId = max(lastAlertId, id)
        }
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
        menu.autoenablesItems = false
        func sym(_ n: String, _ c: NSColor? = nil) -> NSImage? {
            var conf = NSImage.SymbolConfiguration(pointSize: 13, weight: .regular)
            if let c = c { conf = conf.applying(NSImage.SymbolConfiguration(paletteColors: [c])) }
            return NSImage(systemSymbolName: n, accessibilityDescription: nil)?.withSymbolConfiguration(conf)
        }
        @discardableResult
        func add(_ t: String, _ a: Selector?, _ k: String = "", icon: String? = nil, color: NSColor? = nil,
                 on: Bool = false, to m: NSMenu? = nil, obj: Any? = nil) -> NSMenuItem {
            let i = NSMenuItem(title: t, action: a, keyEquivalent: k)
            i.target = self
            i.state = on ? .on : .off
            i.representedObject = obj
            if let n = icon { i.image = sym(n, color) }
            (m ?? menu).addItem(i)
            return i
        }
        func header(_ t: String) {
            let i = NSMenuItem(title: t, action: nil, keyEquivalent: "")
            i.attributedTitle = NSAttributedString(string: t.uppercased(), attributes: [
                .font: NSFont.systemFont(ofSize: 10.5, weight: .semibold), .foregroundColor: NSColor.secondaryLabelColor, .kern: 0.6])
            i.isEnabled = false
            menu.addItem(i)
        }
        func sub(_ t: String, icon: String) -> NSMenu {
            let m = NSMenu()
            let i = add(t, nil, icon: icon)
            i.submenu = m
            return m
        }

        // κάρτα κατάστασης
        let card = NSMenuItem()
        let hv = NSHostingView(rootView: StatusCard(m: cardModel()))
        hv.frame = NSRect(x: 0, y: 0, width: 330, height: hv.fittingSize.height)
        card.view = hv
        menu.addItem(card)
        menu.addItem(.separator())

        let ready = backend.port != nil
        let recent = (status["recent"] as? [[String: Any]]) ?? []
        if ready {
            header("Πρόσφατες ειδοποιήσεις")
            if recent.isEmpty {
                add("Τίποτα ύποπτο — όλα ήσυχα", nil, icon: "checkmark.circle", color: .systemGreen).isEnabled = false
            }
            for a in recent.prefix(5) {
                let sev = a["sev"] as? String ?? "low"
                let col: NSColor = sev == "high" ? .systemRed : sev == "med" ? .systemOrange : .systemYellow
                let i = add("", #selector(openAlert(_:)), icon: "circle.fill", color: col, obj: a["actor"] as? String)
                let t = NSMutableAttributedString(string: (a["type"] as? String ?? "").prefix(42) + "  ",
                                                  attributes: [.font: NSFont.menuFont(ofSize: 13)])
                t.append(NSAttributedString(string: "\(a["actor"] as? String ?? "") · \(ago(a["t"] as? Double))",
                                            attributes: [.font: NSFont.monospacedDigitSystemFont(ofSize: 11, weight: .regular),
                                                         .foregroundColor: NSColor.secondaryLabelColor]))
                i.attributedTitle = t
            }
            if (status["alerts"] as? Int ?? 0) > recent.count {
                add("Όλες οι ειδοποιήσεις (\(status["alerts"] as? Int ?? 0))…", #selector(goTab(_:)), icon: "list.bullet", obj: "alerts")
            }
            menu.addItem(.separator())
        }

        add("Άνοιγμα NetWatch", #selector(showWindow), "o", icon: "macwindow")
        let go = sub("Μετάβαση σε", icon: "arrow.right.circle")
        for (t, tab, ic) in [("Αρχική", "home", "house"), ("Ζωντανός χάρτης", "map", "globe.europe.africa"),
                             ("Δίκτυο σπιτιού", "lan", "network"), ("Ειδοποιήσεις", "alerts", "exclamationmark.triangle"),
                             ("Συσκευές", "devices", "laptopcomputer.and.iphone"), ("Homelab", "health", "server.rack"),
                             ("Ροές (NetFlow)", "flows", "water.waves"), ("Καθυστέρηση", "lat", "waveform.path.ecg"),
                             ("Ανωνυμία", "priv", "eye.slash"), ("Λειτουργία", "ops", "wrench.and.screwdriver")] {
            add(t, #selector(goTab(_:)), icon: ic, to: go, obj: tab)
        }
        add("Οθόνη τοίχου (NOC)", #selector(openNoc), "n", icon: "tv")
        menu.addItem(.separator())

        header("Γρήγορα")
        let wr = status["wifi_running"] as? Bool ?? false
        add(wr ? "Έλεγχος Wi‑Fi… (τρέχει)" : "Έλεγχος Wi‑Fi τώρα", ready && !wr ? #selector(wifiCheck) : nil, icon: "wifi")
            .isEnabled = ready && !wr
        add("Έλεγχος διαρροών (VPN / Tor)", ready ? #selector(leakCheck) : nil, icon: "eye.trianglebadge.exclamationmark").isEnabled = ready
        let mt = status["maint"] as? [String: Any]
        let muted = mt?["active"] as? Bool ?? false
        let mm = sub(muted ? "Σίγαση: ενεργή" : "Σίγαση ειδοποιήσεων", icon: muted ? "bell.slash.fill" : "bell.slash")
        for (t, mins) in [("30 λεπτά", 30), ("1 ώρα", 60), ("4 ώρες", 240), ("Μέχρι αύριο το πρωί", -1)] {
            add(t, #selector(mute(_:)), to: mm, obj: mins).isEnabled = ready
        }
        mm.addItem(.separator())
        add("Άρση σίγασης", #selector(unmute), icon: "bell", to: mm).isEnabled = ready && muted
        menu.addItem(.separator())

        let modes: [(String, Mode)] = [("Live", .live), ("Demo", .demo), ("PCAP", .pcap)]
        let cur = modes.first { $0.1 == backend.mode }?.0 ?? ""
        let md = sub("Λειτουργία: \(cur)", icon: "dial.medium")
        add("Live — πραγματική κίνηση", #selector(goLive), icon: "dot.radiowaves.left.and.right", on: backend.mode == .live, to: md)
        add("Demo — προσομοίωση", #selector(goDemo), icon: "theatermasks", on: backend.mode == .demo, to: md)
        add("Αναπαραγωγή pcap…", #selector(openPcap), icon: "play.rectangle", on: backend.mode == .pcap, to: md)
        md.addItem(.separator())
        let note = NSMenuItem(title: "Το Live ζητά κωδικό διαχειριστή (καταγραφή πακέτων).", action: nil, keyEquivalent: "")
        note.isEnabled = false
        md.addItem(note)

        let more = sub("Περισσότερα", icon: "ellipsis.circle")
        add("Αναφορά εβδομάδας", ready ? #selector(openReport) : nil, icon: "doc.richtext", to: more).isEnabled = ready
        add("Άνοιγμα στον browser", ready ? #selector(openInBrowser) : nil, icon: "safari", to: more).isEnabled = ready
        add("Φάκελος δεδομένων", #selector(openData), icon: "folder", to: more)
        add("Αρχείο καταγραφής", #selector(openLog), icon: "doc.text.magnifyingglass", to: more)
        if #available(macOS 13.0, *) {
            more.addItem(.separator())
            add("Άνοιγμα κατά τη σύνδεση", #selector(toggleLogin), icon: "power", on: SMAppService.mainApp.status == .enabled, to: more)
        }
        menu.addItem(.separator())
        add("Έξοδος", #selector(quit), "q", icon: "xmark.circle")
    }

    func ago(_ t: Double?) -> String {
        guard let t = t else { return "" }
        let s = max(0, Date().timeIntervalSince1970 - t)
        return s < 60 ? "τώρα" : s < 3600 ? "\(Int(s / 60))′" : s < 86400 ? "\(Int(s / 3600))ω" : "\(Int(s / 86400))μ"
    }

    func cardModel() -> CardModel {
        var c = CardModel()
        c.ready = backend.port != nil
        c.mode = backend.mode.rawValue
        c.iface = status["iface"] as? String ?? ""
        c.high = status["high"] as? Int ?? 0
        c.med = status["med"] as? Int ?? 0
        c.alerts = status["alerts"] as? Int ?? 0
        c.lan = status["lan"] as? Int ?? 0
        c.hosts = status["hosts"] as? Int ?? 0
        c.pps = rates.last?.pps ?? 0
        c.bps = rates.last?.bps ?? 0
        c.spark = rates.map { $0.pps }
        if let h = status["homelab"] as? [String: Any], let tot = h["total"] as? Int, tot > 0 {
            c.homelab = "\(h["up"] as? Int ?? 0)/\(tot)"
            c.homelabDown = (h["down"] as? [String]) ?? []
        }
        if let w = status["wifi"] as? [String: Any] {
            c.wifiSsid = w["ssid"] as? String ?? "Wi‑Fi"
            c.wifiVerdict = w["verdict"] as? String ?? ""
            c.wifiScore = w["score"] as? Int ?? -1
            c.wifi = c.wifiSsid
            c.wifiLevel = w["level"] as? String ?? ""
        }
        if let m = status["maint"] as? [String: Any], m["active"] as? Bool == true {
            let until = m["until"] as? Double ?? 0
            let f = DateFormatter(); f.dateFormat = "HH:mm"
            c.muted = until > 0 ? "Σίγαση έως \(f.string(from: Date(timeIntervalSince1970: until)))" : "Συντήρηση: \(m["name"] as? String ?? "")"
        }
        return c
    }

    // ---- ενέργειες του μενού ----
    func runJS(_ js: String, orLoad q: String) {
        showWindow()
        guard let b = backend.base else { return }
        if web.web.url?.host == "127.0.0.1" {
            web.web.evaluateJavaScript(js) { _, err in if err != nil { self.web.load(URL(string: b.absoluteString + "/?" + q)!) } }
        } else {
            web.load(URL(string: b.absoluteString + "/?" + q)!)
        }
    }
    @objc func goTab(_ s: NSMenuItem) {
        guard let t = s.representedObject as? String else { return }
        let js = (t == "map" || t == "lan") ? "setView('\(t)');showTab('\(t)')" : "setView('page');showTab('\(t)')"
        runJS(js, orLoad: "tab=\(t)")
    }
    @objc func openAlert(_ s: NSMenuItem) {
        guard let ip = s.representedObject as? String, ip.range(of: "^[0-9a-fA-F:.]+$", options: .regularExpression) != nil else {
            return runJS("setView('page');showTab('alerts')", orLoad: "tab=alerts")
        }
        runJS("S.hosts.has('\(ip)')?select('\(ip)'):(setView('page'),showTab('alerts'))", orLoad: "tab=alerts&sel=\(ip)")
    }
    @objc func openNoc() {
        runJS("nocToggle(true)", orLoad: "noc=1")
        if !web.window.styleMask.contains(.fullScreen) { web.window.toggleFullScreen(nil) }
    }
    @objc func leakCheck() {
        backend.post("api/privacy")
        runJS("setView('page');showTab('priv')", orLoad: "tab=priv")
    }
    @objc func mute(_ s: NSMenuItem) {
        var mins = s.representedObject as? Int ?? 30
        if mins < 0 {  // μέχρι αύριο 08:00
            let cal = Calendar.current
            let next = cal.nextDate(after: Date(), matching: DateComponents(hour: 8, minute: 0), matchingPolicy: .nextTime) ?? Date()
            mins = max(1, Int(next.timeIntervalSinceNow / 60))
        }
        backend.post("api/maint/mute", ["minutes": mins, "name": "Από τη γραμμή μενού"]) { _ in DispatchQueue.main.async { self.poll() } }
    }
    @objc func unmute() { backend.post("api/maint/unmute") { _ in DispatchQueue.main.async { self.poll() } } }
    @objc func openReport() { if let b = backend.base { NSWorkspace.shared.open(b.appendingPathComponent("report")) } }
    @objc func toggleLogin() {
        if #available(macOS 13.0, *) {
            let s = SMAppService.mainApp
            do { if s.status == .enabled { try s.unregister() } else { try s.register() } } catch {
                let a = NSAlert(); a.messageText = "Δεν έγινε η αλλαγή"; a.informativeText = error.localizedDescription; a.runModal()
            }
        }
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


// ---------------- Κάρτα κατάστασης στο μενού (SwiftUI) ----------------
struct CardModel {
    var ready = false, mode = "demo", iface = "", high = 0, med = 0, alerts = 0, lan = 0, hosts = 0
    var pps = 0.0, bps = 0.0, spark: [Double] = [], homelab = "—", homelabDown: [String] = []
    var wifi = "", wifiLevel = "", muted = ""
    var wifiSsid = "", wifiVerdict = "", wifiScore = -1
}

struct Sparkline: Shape {
    let v: [Double]
    var closed = false
    func path(in r: CGRect) -> Path {
        var p = Path()
        guard v.count > 1, let mx = v.max(), mx > 0 else { p.move(to: CGPoint(x: 0, y: r.maxY)); p.addLine(to: CGPoint(x: r.maxX, y: r.maxY)); return p }
        for (i, x) in v.enumerated() {
            let pt = CGPoint(x: r.width * CGFloat(i) / CGFloat(v.count - 1), y: r.maxY - r.height * CGFloat(x / mx))
            i == 0 ? p.move(to: pt) : p.addLine(to: pt)
        }
        if closed { p.addLine(to: CGPoint(x: r.maxX, y: r.maxY)); p.addLine(to: CGPoint(x: 0, y: r.maxY)); p.closeSubpath() }
        return p
    }
}

struct StatusCard: View {
    let m: CardModel
    var level: (String, Color, String) {
        if !m.ready { return ("shield", .secondary, "Ξεκινά…") }
        if m.high > 0 { return ("exclamationmark.shield.fill", .red, m.high == 1 ? "1 σοβαρή ειδοποίηση" : "\(m.high) σοβαρές ειδοποιήσεις") }
        if m.med > 0 { return ("shield.lefthalf.filled", .orange, m.med == 1 ? "1 ειδοποίηση προς έλεγχο" : "\(m.med) ειδοποιήσεις προς έλεγχο") }
        return ("checkmark.shield.fill", .green, "Όλα ήσυχα")
    }
    var modeTag: (String, Color) {
        switch m.mode { case "live": return ("LIVE", .red); case "pcap": return ("PCAP", .purple); default: return ("DEMO", .yellow) }
    }
    func fmtRate(_ b: Double) -> String {
        b >= 1e6 ? String(format: "%.1f MB/s", b / 1e6) : b >= 1e3 ? String(format: "%.0f KB/s", b / 1e3) : String(format: "%.0f B/s", b)
    }
    func tile(_ v: String, _ l: String, _ ic: String, _ c: Color) -> some View {
        VStack(spacing: 3) {
            Image(systemName: ic).font(.system(size: 12)).foregroundColor(c.opacity(0.9))
            Text(v).font(.system(size: 19, weight: .semibold, design: .rounded)).monospacedDigit().foregroundColor(c)
            Text(l).font(.system(size: 9.5, weight: .medium)).foregroundColor(.secondary).lineLimit(1).minimumScaleFactor(0.7)
        }
        .frame(maxWidth: .infinity)
        .padding(.vertical, 9)
        .background(RoundedRectangle(cornerRadius: 10).fill(Color.primary.opacity(0.05)))
        .overlay(RoundedRectangle(cornerRadius: 10).strokeBorder(Color.primary.opacity(0.06), lineWidth: 1))
    }
    var wifiColor: Color { m.wifiLevel == "bad" ? .red : m.wifiLevel == "warn" ? .orange : .green }
    func row<V: View>(_ ic: String, _ color: Color, @ViewBuilder _ content: () -> V) -> some View {
        HStack(spacing: 7) {
            Image(systemName: ic).font(.system(size: 11)).foregroundColor(color).frame(width: 16)
            content()
            Spacer(minLength: 0)
        }
    }
    var body: some View {
        VStack(alignment: .leading, spacing: 11) {
            // ── κεφαλίδα ──
            HStack(spacing: 10) {
                Image(systemName: level.0).font(.system(size: 17, weight: .medium)).foregroundColor(level.1)
                    .frame(width: 36, height: 36)
                    .background(RoundedRectangle(cornerRadius: 10).fill(level.1.opacity(0.14)))
                VStack(alignment: .leading, spacing: 2) {
                    HStack(spacing: 6) {
                        Text("NetWatch").font(.system(size: 14, weight: .bold))
                        Text(modeTag.0).font(.system(size: 9, weight: .heavy))
                            .foregroundColor(modeTag.1)
                            .padding(.horizontal, 5).padding(.vertical, 1.5)
                            .background(Capsule().fill(modeTag.1.opacity(0.16)))
                        if !m.iface.isEmpty { Text(m.iface).font(.system(size: 10, design: .monospaced)).foregroundColor(.secondary) }
                    }
                    Text(level.2).font(.system(size: 11.5, weight: .medium))
                        .foregroundColor(m.high > 0 || m.med > 0 ? level.1 : .secondary)
                }
                Spacer()
            }
            if m.ready {
                // ── κίνηση + sparkline ──
                VStack(alignment: .leading, spacing: 3) {
                    HStack {
                        Text("ΚΙΝΗΣΗ").font(.system(size: 9, weight: .semibold)).tracking(0.6).foregroundColor(.secondary)
                        Spacer()
                        Text(String(format: "%.0f πακ/s", m.pps)).font(.system(size: 10.5, weight: .semibold, design: .monospaced)).foregroundColor(.primary)
                        Text("· " + fmtRate(m.bps)).font(.system(size: 10.5, design: .monospaced)).foregroundColor(.secondary)
                    }
                    ZStack(alignment: .bottomLeading) {
                        Sparkline(v: m.spark, closed: true)
                            .fill(LinearGradient(colors: [Color.accentColor.opacity(0.30), Color.accentColor.opacity(0.02)], startPoint: .top, endPoint: .bottom))
                        Sparkline(v: m.spark).stroke(Color.accentColor, style: StrokeStyle(lineWidth: 1.6, lineJoin: .round))
                    }.frame(height: 30)
                }
                // ── πλακίδια ──
                HStack(spacing: 7) {
                    tile("\(m.lan)", "συσκευές", "laptopcomputer", .primary)
                    tile("\(m.alerts)", "ειδοποιήσεις", "bell.fill", m.high > 0 ? .red : m.med > 0 ? .orange : .green)
                    tile(m.homelab, "homelab", "server.rack", m.homelabDown.isEmpty ? .green : .orange)
                }
                // ── γραμμές κατάστασης ──
                VStack(alignment: .leading, spacing: 7) {
                    if !m.homelabDown.isEmpty {
                        row("bolt.horizontal.circle.fill", .orange) {
                            Text("Εκτός: " + m.homelabDown.joined(separator: ", ")).font(.system(size: 11.5)).foregroundColor(.orange).lineLimit(1)
                        }
                    }
                    if !m.wifiSsid.isEmpty {
                        row("wifi", wifiColor) {
                            Text(m.wifiSsid).font(.system(size: 11.5, weight: .medium)).lineLimit(1)
                            if m.wifiScore >= 0 {
                                Text("\(m.wifiScore)/100").font(.system(size: 10.5, weight: .semibold, design: .rounded)).monospacedDigit()
                                    .foregroundColor(wifiColor)
                                    .padding(.horizontal, 6).padding(.vertical, 1)
                                    .background(Capsule().fill(wifiColor.opacity(0.14)))
                            }
                        }
                    }
                    if !m.muted.isEmpty {
                        row("bell.slash.fill", .purple) {
                            Text(m.muted).font(.system(size: 11.5)).foregroundColor(.purple).lineLimit(1)
                        }
                    }
                }
            }
        }
        .padding(.horizontal, 14).padding(.vertical, 10)
        .frame(width: 330, alignment: .leading)
    }
}
