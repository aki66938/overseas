import Cocoa

@main
struct MenuBarHostTests {
  static func main() {
    let app = NSApplication.shared
    app.setActivationPolicy(.accessory)
    let controller = NSViewController()
    controller.view = NSView(frame: NSRect(x: 0, y: 0, width: 480, height: 224))
    let host = MenuBarHost(controller: controller)
    precondition(!host.popover.isShown, "Startup must not show a window")
    precondition(host.popover.contentViewController === controller)
    precondition(host.popover.contentSize == NSSize(width: 480, height: 224))
    precondition(host.popover.behavior == .transient)
    host.close()
    precondition(host.popover.contentViewController === controller, "Closing must retain engine owner")
    precondition(MenuBarHost.contentSize(for: NSSize(width: 1440, height: 900)) == NSSize(width: 480, height: 224))
    precondition(MenuBarHost.contentSize(for: NSSize(width: 400, height: 210)) == NSSize(width: 368, height: 178))
    if CommandLine.arguments.contains("--interactive") {
      app.finishLaunching()
      // Status-bar button layout is delivered by the graphical event loop.
      RunLoop.main.run(until: Date(timeIntervalSinceNow: 0.5))
      host.show()
      print("after show: shown=\(host.popover.isShown) active=\(app.isActive) windows=\(app.windows.map { String(describing: type(of: $0)) + ":" + String($0.isVisible) })")
      fflush(stdout)
      RunLoop.main.run(until: Date(timeIntervalSinceNow: 0.2))
      precondition(host.popover.isShown, "Popover must open in graphical session")
      host.toggle()
      precondition(!host.popover.isShown)
      host.toggle()
      precondition(host.popover.isShown)
      precondition(host.popover.contentViewController === controller)
      host.close()
    }
    print("MenuBarHost tests passed")
  }
}
