import Cocoa
import FlutterMacOS

final class AccessBridge: NSObject {
  private let access: FlutterMethodChannel
  private let shell: FlutterMethodChannel
  private weak var window: NSWindow?
  private let item = NSStatusBar.system.statusItem(withLength: NSStatusItem.squareLength)
  private let summary = NSMenuItem(title: "服务暂不可用", action: nil, keyEquivalent: "")
  private let toggle = NSMenuItem(title: "开启海外访问", action: #selector(toggleAccess), keyEquivalent: "")
  private let details = NSMenuItem(title: "连接详情", action: #selector(showDetails), keyEquivalent: "")
  private let quit = NSMenuItem(title: "断开并退出", action: #selector(safeExit), keyEquivalent: "")
  private var action = ""
  private var pending = 0
  private var exiting = false
  var canTerminate = false

  init(controller: FlutterViewController, window: NSWindow) {
    self.window = window
    access = FlutterMethodChannel(name: "regen_access/access", binaryMessenger: controller.engine.binaryMessenger)
    shell = FlutterMethodChannel(name: "regen_access/shell", binaryMessenger: controller.engine.binaryMessenger)
    super.init()
    let menu = NSMenu()
    menu.autoenablesItems = false
    summary.isEnabled = false
    menu.addItem(summary)
    menu.addItem(.separator())
    let show = NSMenuItem(title: "显示主窗口", action: #selector(showHome), keyEquivalent: "")
    for entry in [show, details, toggle, quit] { entry.target = self; menu.addItem(entry) }
    toggle.isEnabled = false; details.isEnabled = false
    item.menu = menu
    updateIcon(connected: false)
    access.setMethodCallHandler { [weak self] call, result in
      guard let self = self else { return }
      guard call.method == "request", let args = call.arguments as? [String: Any], AccessTransport.validRequest(args) else {
        result(FlutterError(code: "pre_dispatch", message: "Invalid request", details: nil)); return
      }
      guard self.pending < 8 else { result(FlutterError(code: "pre_dispatch", message: "Transport busy", details: nil)); return }
      self.pending += 1
      DispatchQueue.global(qos: .userInitiated).async {
        let response: Any
        do { response = try AccessTransport.request(args) }
        catch let failure as TransportFailure { response = FlutterError(code: failure.code, message: "Local service unavailable", details: nil) }
        catch { response = FlutterError(code: "uncertain", message: "Local service response failed", details: nil) }
        DispatchQueue.main.async { self.pending -= 1; result(response) }
      }
    }
    shell.setMethodCallHandler { [weak self] call, result in
      guard call.method == "update", let state = call.arguments as? [String: Any] else { result(FlutterMethodNotImplemented); return }
      self?.update(state); result(nil)
    }
  }

  private func update(_ state: [String: Any]) {
    guard let label = state["label"] as? String, let enabled = state["enabled"] as? Bool,
          let text = state["summary"] as? String, let showDetails = state["details"] as? Bool,
          let nextAction = state["action"] as? String,
          ["", "connect", "disconnect", "restore"].contains(nextAction) else { return }
    summary.title = text; toggle.title = label; action = nextAction
    toggle.isEnabled = enabled && !exiting
    details.isEnabled = showDetails
    item.button?.toolTip = "RegenBio 海外访问 · " + text
    updateIcon(connected: nextAction == "disconnect")
  }
  private func updateIcon(connected: Bool) {
    let icon = NSImage(systemSymbolName: connected ? "network.badge.shield.half.filled" : "network", accessibilityDescription: "RegenBio 海外访问")
    icon?.isTemplate = true; item.button?.image = icon
  }
  private func show() { window?.makeKeyAndOrderFront(nil); NSApp.activate(ignoringOtherApps: true) }
  @objc private func showHome() { shell.invokeMethod("home", arguments: nil); show() }
  @objc private func showDetails() { shell.invokeMethod("details", arguments: nil); show() }
  @objc private func toggleAccess() { if toggle.isEnabled { shell.invokeMethod("action", arguments: action) } }
  @objc func safeExit() {
    guard !exiting else { return }
    exiting = true; toggle.isEnabled = false; quit.isEnabled = false
    shell.invokeMethod("safeExit", arguments: nil) { [weak self] result in
      guard let self = self else { return }
      if let safe = result as? Bool, safe {
        self.canTerminate = true; NSApp.terminate(nil)
      } else {
        self.exiting = false; self.quit.isEnabled = true; self.show()
      }
    }
  }
}
