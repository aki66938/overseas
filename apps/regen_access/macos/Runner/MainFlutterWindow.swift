import Cocoa
import FlutterMacOS

class MainFlutterWindow: NSWindow, NSWindowDelegate {
  var accessBridge: AccessBridge?
  override func awakeFromNib() {
    let flutterViewController = FlutterViewController()
    let windowFrame = self.frame
    self.contentViewController = flutterViewController
    self.setFrame(windowFrame, display: true)
    self.styleMask.remove(.resizable)
    self.setContentSize(NSSize(width: 480, height: 224))
    self.standardWindowButton(.zoomButton)?.isHidden = true
    self.collectionBehavior = [.fullScreenNone]
    self.delegate = self
    self.title = "RegenBio 海外访问"

    RegisterGeneratedPlugins(registry: flutterViewController)
    accessBridge = AccessBridge(controller: flutterViewController, window: self)

    super.awakeFromNib()
  }

  func windowShouldClose(_ sender: NSWindow) -> Bool {
    sender.orderOut(nil)
    return false
  }
}
