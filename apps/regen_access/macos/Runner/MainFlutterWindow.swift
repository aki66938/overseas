import Cocoa
import FlutterMacOS

class MainFlutterWindow: NSWindow {
  override func awakeFromNib() {
    let flutterViewController = FlutterViewController()
    let windowFrame = self.frame
    self.contentViewController = flutterViewController
    self.setFrame(windowFrame, display: true)
    self.setContentSize(NSSize(width: 460, height: 540))
    self.title = "RegenBio 海外访问"

    RegisterGeneratedPlugins(registry: flutterViewController)

    super.awakeFromNib()
  }
}
