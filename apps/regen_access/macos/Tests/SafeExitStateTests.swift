import Foundation

@main
struct SafeExitStateTests {
  static func main() {
    var state = SafeExitState()
    state.update(actionEnabled: true)
    precondition(state.actionEnabled)
    precondition(state.begin())
    precondition(!state.begin(), "Repeated exit must be ignored")
    state.update(actionEnabled: true)
    precondition(!state.actionEnabled, "Polling must not re-enable actions during exit")
    state.finish(restored: false)
    precondition(!state.canTerminate)
    precondition(state.actionEnabled, "Failed exit must restore last action permission")
    precondition(state.begin())
    state.update(actionEnabled: false)
    state.finish(restored: false)
    precondition(!state.actionEnabled, "Disabled service action must remain disabled")
    precondition(state.begin())
    state.finish(restored: true)
    precondition(state.canTerminate)
    precondition(!state.actionEnabled)
    precondition(!state.begin())
    print("SafeExitState tests passed")
  }
}
