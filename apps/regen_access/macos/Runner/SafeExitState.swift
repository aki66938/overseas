/// Keeps tray actions disabled until restoration has been confirmed.
struct SafeExitState {
  private var lastActionEnabled = false
  private(set) var exiting = false
  private(set) var canTerminate = false
  var actionEnabled: Bool { lastActionEnabled && !exiting }

  mutating func update(actionEnabled: Bool) { lastActionEnabled = actionEnabled }
  mutating func begin() -> Bool {
    guard !exiting else { return false }
    exiting = true
    return true
  }
  mutating func finish(restored: Bool) {
    canTerminate = restored
    exiting = restored
  }
}
