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

let c = CGPoint(x: 512, y: 500), r: CGFloat = 270
let cyan = NSColor(red: 0.25, green: 0.85, blue: 1, alpha: 1)
ctx.saveGState()
ctx.setShadow(offset: .zero, blur: 40, color: cyan.withAlphaComponent(0.8).cgColor)
cyan.setStroke()
let globe = NSBezierPath(ovalIn: CGRect(x: c.x - r, y: c.y - r, width: 2 * r, height: 2 * r))
globe.lineWidth = 22
globe.stroke()
ctx.restoreGState()
cyan.withAlphaComponent(0.55).setStroke()
for k in [0.45, 0.85] as [CGFloat] {  // μεσημβρινοί
    let p = NSBezierPath(ovalIn: CGRect(x: c.x - r * k, y: c.y - r, width: 2 * r * k, height: 2 * r))
    p.lineWidth = 10
    p.stroke()
}
for dy in [-0.5, 0, 0.5] as [CGFloat] {  // παράλληλοι
    let y = c.y + dy * r, w = sqrt(1 - dy * dy) * r
    let p = NSBezierPath()
    p.move(to: CGPoint(x: c.x - w, y: y))
    p.line(to: CGPoint(x: c.x + w, y: y))
    p.lineWidth = 10
    p.stroke()
}
// τόξο σύνδεσης προς τον «επιτιθέμενο»
let arc = NSBezierPath()
arc.move(to: CGPoint(x: 380, y: 430))
arc.curve(to: CGPoint(x: 700, y: 640), controlPoint1: CGPoint(x: 430, y: 700), controlPoint2: CGPoint(x: 600, y: 760))
NSColor(red: 1, green: 0.85, blue: 0.3, alpha: 0.95).setStroke()
arc.lineWidth = 16
arc.lineCapStyle = .round
arc.stroke()
NSColor(red: 0.3, green: 0.95, blue: 0.6, alpha: 1).setFill()
NSBezierPath(ovalIn: CGRect(x: 350, y: 400, width: 60, height: 60)).fill()
ctx.saveGState()
let red = NSColor(red: 1, green: 0.23, blue: 0.36, alpha: 1)
ctx.setShadow(offset: .zero, blur: 50, color: red.cgColor)
red.setFill()
NSBezierPath(ovalIn: CGRect(x: 662, y: 602, width: 76, height: 76)).fill()
ctx.restoreGState()
red.withAlphaComponent(0.5).setStroke()
let ring = NSBezierPath(ovalIn: CGRect(x: 630, y: 570, width: 140, height: 140))
ring.lineWidth = 8
ring.stroke()
img.unlockFocus()

let rep = NSBitmapImageRep(data: img.tiffRepresentation!)!
try! rep.representation(using: .png, properties: [:])!.write(to: URL(fileURLWithPath: CommandLine.arguments[1]))
