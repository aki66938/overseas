import Cocoa
import FlutterMacOS

final class AccessBridge: NSObject {
  private let access: FlutterMethodChannel
  private let shell: FlutterMethodChannel
  private let host: MenuBarHost
  private let summary = NSMenuItem(title: "服务暂不可用", action: nil, keyEquivalent: "")
  private let toggle = NSMenuItem(title: "开启海外访问", action: #selector(toggleAccess), keyEquivalent: "")
  private let quit = NSMenuItem(title: "断开并退出", action: #selector(safeExit), keyEquivalent: "")
  private var action = ""
  private var pending = 0
  private var exitState = SafeExitState()
  var canTerminate: Bool { exitState.canTerminate }

  init(controller: FlutterViewController, host: MenuBarHost) {
    self.host = host
    access = FlutterMethodChannel(name: "regen_access/access", binaryMessenger: controller.engine.binaryMessenger)
    shell = FlutterMethodChannel(name: "regen_access/shell", binaryMessenger: controller.engine.binaryMessenger)
    super.init()
    let menu = NSMenu()
    menu.autoenablesItems = false
    summary.isEnabled = false
    menu.addItem(summary)
    menu.addItem(.separator())
    for entry in [toggle, quit] { entry.target = self; menu.addItem(entry) }
    toggle.isEnabled = false
    host.setMenu(menu)
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
          let text = state["summary"] as? String,
          let nextAction = state["action"] as? String,
          ["", "connect", "disconnect", "restore"].contains(nextAction) else { return }
    summary.title = text; toggle.title = label; action = nextAction
    exitState.update(actionEnabled: enabled)
    toggle.isEnabled = exitState.actionEnabled
    host.update(connected: nextAction == "disconnect", summary: text)
  }
  @objc private func toggleAccess() { if toggle.isEnabled { shell.invokeMethod("action", arguments: action) } }
  @objc func safeExit() {
    guard exitState.begin() else { return }
    toggle.isEnabled = false; quit.isEnabled = false
    shell.invokeMethod("safeExit", arguments: nil) { [weak self] result in
      guard let self = self else { return }
      self.exitState.finish(restored: (result as? Bool) == true)
      if self.exitState.canTerminate {
        NSApp.terminate(nil)
      } else {
        self.quit.isEnabled = true
        self.toggle.isEnabled = self.exitState.actionEnabled
        self.host.show()
        let alert = NSAlert()
        alert.messageText = "网络尚未恢复，请重试"
        alert.addButton(withTitle: "好")
        if let window = self.host.popover.contentViewController?.view.window {
          alert.beginSheetModal(for: window)
        }
      }
    }
  }
}
