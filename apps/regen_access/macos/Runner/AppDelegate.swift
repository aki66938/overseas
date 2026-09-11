import Cocoa
import FlutterMacOS

@main
class AppDelegate: FlutterAppDelegate {
  private var host: MenuBarHost?
  private var accessBridge: AccessBridge?

  override func applicationDidFinishLaunching(_ notification: Notification) {
    NSApp.setActivationPolicy(.accessory)
    let controller = FlutterViewController()
    RegisterGeneratedPlugins(registry: controller)
    let host = MenuBarHost(controller: controller)
    self.host = host
    accessBridge = AccessBridge(controller: controller, host: host)
    super.applicationDidFinishLaunching(notification)
  }

  override func applicationShouldHandleReopen(_ sender: NSApplication, hasVisibleWindows flag: Bool) -> Bool {
    host?.show()
    return false
  }

  override func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool {
    return false
  }

  override func applicationShouldTerminate(_ sender: NSApplication) -> NSApplication.TerminateReply {
    guard let bridge = accessBridge else { return .terminateCancel }
    if bridge.canTerminate { return .terminateNow }
    bridge.safeExit()
    return .terminateCancel
  }

  override func applicationSupportsSecureRestorableState(_ app: NSApplication) -> Bool {
    return true
  }
}
