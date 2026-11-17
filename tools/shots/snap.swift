// Στιγμιότυπα του NetWatch χωρίς Chrome: ανοίγει μια σελίδα σε αόρατο WebKit (WKWebView) και γράφει PNG.
//
//   swiftc -O tools/shots/snap.swift -o build/snap
//   build/snap <url> <out.png> [--size 1280x800] [--wait 6] [--js "κώδικας"] [--frames 40 --every 0.1]
//
// --js:     τρέχει πριν από τη λήψη (π.χ. άνοιγμα μιας συσκευής), και περιμένει --after δευτ. (1″)
// --frames: αντί για ένα PNG γράφει out-000.png, out-001.png, … (για GIF με ffmpeg)
// Κάθε εκτέλεση έχει καθαρή μνήμη (όχι cookies / localStorage από προηγούμενες).
import Cocoa
import WebKit

struct Opts {
    var url = "", out = "", w = 1280.0, h = 800.0, wait = 6.0, js: String? = nil, after = 1.0, frames = 1, every = 0.1
}

func parse() -> Opts {
    var o = Opts(), a = Array(CommandLine.arguments.dropFirst()), pos: [String] = []
    while !a.isEmpty {
        let k = a.removeFirst()
        switch k {
        case "--size": let p = a.removeFirst().split(separator: "x"); o.w = Double(p[0])!; o.h = Double(p[1])!
        case "--wait": o.wait = Double(a.removeFirst())!
        case "--js": o.js = a.removeFirst()
        case "--after": o.after = Double(a.removeFirst())!
        case "--frames": o.frames = Int(a.removeFirst())!
        case "--every": o.every = Double(a.removeFirst())!
        default: pos.append(k)
        }
    }
    guard pos.count == 2 else {
        FileHandle.standardError.write("χρήση: snap <url> <out.png> [--size WxH] [--wait s] [--js code] [--frames n --every s]\n".data(using: .utf8)!)
        exit(2)
    }
    o.url = pos[0]; o.out = pos[1]
    return o
}

final class Snap: NSObject, WKNavigationDelegate {
    let o: Opts, web: WKWebView, win: NSWindow
    var n = 0

    init(_ o: Opts) {
        self.o = o
        let cfg = WKWebViewConfiguration()
        cfg.websiteDataStore = .nonPersistent()
        // εκτός οθόνης το WebKit παγώνει το requestAnimationFrame (ο χάρτης δεν ζωγραφίζεται): εδώ, μόνο για τα στιγμιότυπα, γίνεται timer 60fps
        cfg.userContentController.addUserScript(WKUserScript(source:
            "window.requestAnimationFrame=cb=>setTimeout(()=>cb(performance.now()),16);window.cancelAnimationFrame=id=>clearTimeout(id);",
            injectionTime: .atDocumentStart, forMainFrameOnly: true))
        // και τα CSS animations μένουν παγωμένα στο πρώτο καρέ (π.χ. αόρατο popup): τα κλείνουμε στα στιγμιότυπα
        cfg.userContentController.addUserScript(WKUserScript(source:
            "document.addEventListener('DOMContentLoaded',()=>{const s=document.createElement('style');s.textContent='*,*::before,*::after{animation:none!important;transition:none!important}';document.head.appendChild(s)})",
            injectionTime: .atDocumentStart, forMainFrameOnly: true))
        let r = NSRect(x: 0, y: 0, width: o.w, height: o.h)
        web = WKWebView(frame: r, configuration: cfg)
        // παράθυρο εκτός οθόνης: «ορατό» για το WebKit (τρέχουν τα animations του χάρτη), αλλά δεν το βλέπεις
        win = NSWindow(contentRect: r, styleMask: [.borderless], backing: .buffered, defer: false)
        super.init()
        win.contentView = web
        win.setFrameOrigin(NSPoint(x: -30000, y: -30000))
        win.orderFrontRegardless()
        web.navigationDelegate = self
        let u = URL(string: o.url)!
        if u.isFileURL { web.loadFileURL(u, allowingReadAccessTo: u.deletingLastPathComponent().deletingLastPathComponent()) }
        else { web.load(URLRequest(url: u)) }
        DispatchQueue.main.asyncAfter(deadline: .now() + o.wait + 60) { self.fail("timeout") }
    }

    func fail(_ m: String) {
        FileHandle.standardError.write("snap: \(m)\n".data(using: .utf8)!)
        exit(1)
    }

    func webView(_ w: WKWebView, didFail _: WKNavigation!, withError e: Error) { fail(e.localizedDescription) }
    func webView(_ w: WKWebView, didFailProvisionalNavigation _: WKNavigation!, withError e: Error) { fail(e.localizedDescription) }

    func webView(_ w: WKWebView, didFinish _: WKNavigation!) {
        DispatchQueue.main.asyncAfter(deadline: .now() + o.wait) {
            guard let js = self.o.js else { return self.shoot() }
            self.web.evaluateJavaScript(js) { res, err in
                if let err = err { FileHandle.standardError.write("snap: js: \(err)\n".data(using: .utf8)!) }
                if let res = res, !(res is NSNull) { print("js → \(res)") }
                DispatchQueue.main.asyncAfter(deadline: .now() + self.o.after) { self.shoot() }
            }
        }
    }

    func path(_ i: Int) -> String {
        if o.frames == 1 { return o.out }
        let base = (o.out as NSString).deletingPathExtension
        return String(format: "%@-%03d.png", base, i)
    }

    // Το snapshot του WebKit δεν πιάνει τα <canvas> (χάρτης, γραφήματα) όταν το παράθυρο είναι εκτός οθόνης:
    // πριν από κάθε λήψη βάζουμε πάνω τους μια <img> με το περιεχόμενό τους, και τη βγάζουμε μετά.
    static let canvasToImg = """
    (()=>{for(const x of document.querySelectorAll('img.__snap'))x.remove();
     for(const c of document.querySelectorAll('canvas.__snaphid')){c.classList.remove('__snaphid');c.style.visibility=''}
     for(const c of document.querySelectorAll('canvas')){if(!c.offsetWidth||!c.offsetHeight)continue;let u;try{u=c.toDataURL()}catch(e){continue}
      const i=new Image(),cs=getComputedStyle(c);i.className='__snap';i.src=u;
      if(cs.position==='absolute'||cs.position==='fixed')Object.assign(i.style,{position:cs.position,left:c.offsetLeft+'px',top:c.offsetTop+'px',width:c.offsetWidth+'px',height:c.offsetHeight+'px',pointerEvents:'none'});
      else Object.assign(i.style,{width:c.offsetWidth+'px',height:c.offsetHeight+'px',verticalAlign:cs.verticalAlign,display:cs.display==='block'?'block':'inline-block',margin:cs.margin});
      if(!(cs.position==='absolute'||cs.position==='fixed')){c.classList.add('__snaphid');c.style.display='none';i.dataset.disp=cs.display}
      c.insertAdjacentElement('afterend',i)}})()
    """
    static let restore = "(()=>{for(const x of document.querySelectorAll('img.__snap'))x.remove();for(const c of document.querySelectorAll('canvas.__snaphid')){c.classList.remove('__snaphid');c.style.display=''}})()"

    func shoot() {
        web.evaluateJavaScript(Snap.canvasToImg) { _, _ in
            DispatchQueue.main.asyncAfter(deadline: .now() + 0.12) { self.take() }
        }
    }

    func take() {
        let c = WKSnapshotConfiguration()
        c.snapshotWidth = NSNumber(value: o.w)  // σε points· σε Retina βγαίνει 2×
        web.takeSnapshot(with: c) { img, err in
            guard let img = img, let tiff = img.tiffRepresentation, let rep = NSBitmapImageRep(data: tiff),
                  let png = rep.representation(using: .png, properties: [:]) else { return self.fail("snapshot: \(String(describing: err))") }
            do { try png.write(to: URL(fileURLWithPath: self.path(self.n))) } catch { self.fail("\(error)") }
            self.n += 1
            self.web.evaluateJavaScript(Snap.restore, completionHandler: nil)
            if self.n >= self.o.frames { exit(0) }
            DispatchQueue.main.asyncAfter(deadline: .now() + self.o.every) { self.shoot() }
        }
    }
}

let app = NSApplication.shared
app.setActivationPolicy(.prohibited)
let snap = Snap(parse())
app.run()
