# RegenBio 海外访问 — shared desktop pages

Native Flutter Windows/macOS content, based on `docs/design/three-platform-approved.html`.
Flutter 3.47.2 / Dart 3.13.2. Linux remains CLI only.

```powershell
$env:CI = 'true'
flutter pub get
flutter analyze
flutter test
flutter build windows --release
```

The production entry uses `UnavailableAccessClient` until Task 7 provides the native
APIv1 bridge. It displays 服务暂不可用 and cannot claim a fictional connection.
Inject `AccessClient` into `MyApp`; transport framing, request IDs, native lifecycle,
tray, close-to-hide and service installation are separate work. `Status.fromResponse`
projects the decoded APIv1 response into display state; the transport must validate
frame size and response correlation before calling it.

Both pages share a 460×540 logical content shell. Native runners start at this content
size; their platform caption is additional. Narrow windows and large text scroll.
OS-specific window sizing constraints and lifecycle integration remain Task 7 gates.

Status polling is serialized every 3 seconds. Observation budgets are 8 seconds for
status, 130 for connect, 100 for disconnect, and 10 for probes; lifecycle budgets allow
grace beyond the service's 120/90-second deadlines. Crossing a budget clears the old
connection claim but retains request ownership until the original Future completes.
A late status sample is discarded; a completed lifecycle action gets a fresh status read.
There is no UI-side cancellation pretending to stop server work. Task 7 transport must
settle lifecycle Futures only after completion or confirmed cancellation. While a status
read is pending, action buttons are visibly disabled and show the read in progress;
the main connection state and duration remain visible until the status budget expires.
Disposal cancels display timers and prevents follow-up requests, without claiming to
cancel the service operation. User actions are serialized; manual probes are
enabled only while connected, and their completed status is reread from the service.
There is no UI network probing, client failure counting, or persistent generation cache.
Service-authored counters are unknown when absent, pending at 1/2, abnormal at 3.
Successful latency >=1000 ms is slow. Disconnected results are explicitly historical;
starting a connection hides the old results immediately.

Tests use synthetic fixtures only. `test/fonts/README.md` describes the pinned OFL
font and readable Chinese goldens. That font is test-only; production uses system fonts.
Goldens verify Flutter content, not macOS-native appearance or live service integration.
The generated empty macOS XCTest target was removed; no native macOS test pass is claimed.
