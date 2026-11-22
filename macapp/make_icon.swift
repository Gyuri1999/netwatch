// Ζωγραφίζει το εικονίδιο της εφαρμογής (1024×1024 PNG): σκούρο φόντο, «υδρόγειος» και σήμα κινδύνου.
import AppKit

let S: CGFloat = 1024
let img = NSImage(size: NSSize(width: S, height: S))
img.lockFocus()
let ctx = NSGraphicsContext.current!.cgContext
let rect = CGRect(x: 100, y: 100, width: 824, height: 824)
let bg = NSBezierPath(roundedRect: rect, xRadius: 185, yRadius: 185)
NSGradient(colors: [NSColor(red: 0.05, green: 0.11, blue: 0.22, alpha: 1),
                    NSColor(red: 0.01, green: 0.03, blue: 0.07, alpha: 1)])!.draw(in: bg, angle: -90)
NSColor(red: 0.2, green: 0.75, blue: 1, alpha: 0.35).setStroke()
bg.lineWidth = 6
bg.stroke()

let c = CGPoint(x: 512, y: 512), R: CGFloat = 384
let cyan = NSColor(red: 0.24, green: 0.77, blue: 1, alpha: 1)
let red = NSColor(red: 1, green: 0.23, blue: 0.36, alpha: 1)

// σάρωση ραντάρ (πάνω-δεξιά τεταρτημόριο)
let wedge = NSBezierPath()
wedge.move(to: c)
wedge.appendArc(withCenter: c, radius: R, startAngle: 35, endAngle: 90)
wedge.close()
cyan.withAlphaComponent(0.16).setFill()
wedge.fill()

// δακτύλιοι
for (rad, op) in [(R, 0.28), (R * 0.66, 0.45), (R * 0.33, 0.6)] as [(CGFloat, CGFloat)] {
    cyan.withAlphaComponent(op).setStroke()
    let ring = NSBezierPath(ovalIn: CGRect(x: c.x - rad, y: c.y - rad, width: 2 * rad, height: 2 * rad))
    ring.lineWidth = 16
    ring.stroke()
}

// κόμβοι δικτύου + ακτίνες
let nodes = [CGPoint(x: 512 - 244, y: 512 + 152), CGPoint(x: 512 - 168, y: 512 - 224)]
let threat = CGPoint(x: 512 + 216, y: 512 - 168)
cyan.withAlphaComponent(0.5).setStroke()
for n in nodes + [threat] {
    let l = NSBezierPath(); l.move(to: c); l.line(to: n); l.lineWidth = 12; l.lineCapStyle = .round; l.stroke()
}
cyan.setFill()
for n in nodes { NSBezierPath(ovalIn: CGRect(x: n.x - 42, y: n.y - 42, width: 84, height: 84)).fill() }

// κεντρικός κόμβος (λάμψη)
ctx.saveGState()
ctx.setShadow(offset: .zero, blur: 44, color: cyan.withAlphaComponent(0.85).cgColor)
cyan.setFill()
NSBezierPath(ovalIn: CGRect(x: c.x - 78, y: c.y - 78, width: 156, height: 156)).fill()
ctx.restoreGState()

// κόκκινη «απειλή» (λάμψη)
ctx.saveGState()
ctx.setShadow(offset: .zero, blur: 52, color: red.cgColor)
red.setFill()
NSBezierPath(ovalIn: CGRect(x: threat.x - 52, y: threat.y - 52, width: 104, height: 104)).fill()
ctx.restoreGState()
img.unlockFocus()

let rep = NSBitmapImageRep(data: img.tiffRepresentation!)!
try! rep.representation(using: .png, properties: [:])!.write(to: URL(fileURLWithPath: CommandLine.arguments[1]))
