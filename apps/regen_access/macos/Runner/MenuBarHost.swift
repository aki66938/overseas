import Cocoa

/// Owns presentation only. Hiding this panel never touches the network service.
final class MenuBarHost: NSObject {
  let popover = NSPopover()
  private let item = NSStatusBar.system.statusItem(withLength: NSStatusItem.squareLength)
  private var menu: NSMenu?
  private var escapeMonitor: Any?

  init(controller: NSViewController) {
    super.init()
    popover.contentViewController = controller
    popover.contentSize = NSSize(width: 480, height: 224)
    popover.behavior = .transient
    popover.animates = false
    item.button?.target = self
    item.button?.action = #selector(clicked)
    item.button?.sendAction(on: [.leftMouseUp, .rightMouseUp])
    update(connected: false, summary: "服务暂不可用")
    escapeMonitor = NSEvent.addLocalMonitorForEvents(matching: .keyDown) { [weak self] event in
      guard event.keyCode == 53, let self = self, self.popover.isShown else { return event }
      self.close()
      return nil
    }
  }

  deinit {
    if let monitor = escapeMonitor { NSEvent.removeMonitor(monitor) }
    NSStatusBar.system.removeStatusItem(item)
  }

  static func contentSize(for available: NSSize) -> NSSize {
    NSSize(width: min(480, max(1, available.width - 32)),
           height: min(224, max(1, available.height - 32)))
  }

  func setMenu(_ menu: NSMenu) { self.menu = menu }

  func update(connected: Bool, summary: String) {
    let icon = NSImage(systemSymbolName: connected ? "network.badge.shield.half.filled" : "network",
                       accessibilityDescription: "RegenBio 海外访问")
    icon?.isTemplate = true
    item.button?.image = icon
    item.button?.toolTip = "RegenBio 海外访问 · " + summary
  }

  func show() {
    guard let button = item.button else { return }
    if let screen = button.window?.screen {
      popover.contentSize = Self.contentSize(for: screen.visibleFrame.size)
    }
    if !popover.isShown {
      popover.show(relativeTo: button.bounds, of: button, preferredEdge: .minY)
    }
    NSApp.activate(ignoringOtherApps: true)
    popover.contentViewController?.view.window?.makeKey()
  }

  func toggle() { if popover.isShown { close() } else { show() } }
  func close() { popover.performClose(nil) }

  @objc private func clicked() {
    if NSApp.currentEvent?.type == .rightMouseUp {
      close()
      if let button = item.button {
        menu?.popUp(positioning: nil, at: NSPoint(x: 0, y: button.bounds.minY), in: button)
      }
    } else {
      toggle()
    }
  }
}
