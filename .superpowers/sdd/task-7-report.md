# Task 7 Report — Transactional Server Deployment

## Status

Implemented and verified. No real service, firewall, listener, route, ACL, or network mutation was performed during development or tests.

Initial Task 7 commit: `c246c238432270afca904d5424ce7562be42e6cf` (`feat: add transactional sing-box server deployment`).
Review-fix commit: `a061e75a484599c590adccb15866f0dd6073c3e6` (`fix: harden server firewall and directory ownership`).

## TDD Evidence

- Baseline issue at `d0ec5b5`: both PowerShell engines passed 47/48; the sole failure was the legacy Makefile `.PHONY: test build` contract. Parent approved restoring that exact line within Task 7's Makefile scope. Focused RED then GREEN: 4/4 on both engines.
- Main RED: `ServerInstall.Tests.ps1` failed 0/8 on both Windows PowerShell 5.1/Pester 3.4 and PowerShell 7 because `install-server.ps1` and the Makefile target did not exist.
- Main GREEN: focused server suite passed 9/9 on both engines.
- Safety-refinement RED: ordering test failed because config publication preceded ProgramData ACL hardening and the transaction journal followed service start.
- Safety-refinement GREEN: focused server suite passed 10/10 on both engines after ordering ACL before config publication, rehashing installed files, and journaling before service start.
- Output-purity RED: a fake sing-box that wrote a success diagnostic polluted the function result and broke JSON evidence construction. GREEN suppresses native stdout/stderr while still capturing immediate launch and exit status; focused suite returned to 10/10 on both engines.
- Review-hardening RED: five new contracts failed for missing external write-ahead journaling, unsafe compensation ordering, broad server-port allow detection, rollback idempotency, and Make failure propagation. GREEN focused suite: 14/14 on both engines.
- SCM-compatibility RED: direct registration of sing-box 1.13.19 cannot satisfy Windows SCM `ServiceMain`; first-party host and range-aware firewall contracts failed. GREEN adds a minimal project-owned Go SCM host, focused Stop/Shutdown/readiness tests, an offline packaging step, and installer registration of only the pinned host.
- Packaging RED: the first-party host was neither copied into the bundle nor recorded in the bundle manifest. GREEN adds `package-server-service.ps1` and Make targets that copy and rehash the locally built host and atomically add `server_service_sha256` without network access.
- Behavioral-review GREEN adds executed refusal cases for unsupported OS, missing fixed VM IP, sing-box hash mismatch, non-loopback 8080 ownership, CONNECT failure, occupied TCP 18443, and range-based broad firewall exposure. The Go service suite also executes start-failure cleanup and unexpected-child-exit paths.

## Implemented Contracts

- Explicit `Install`, `Status`, and `Rollback` modes; no default mutating mode.
- Fixed VM `172.20.9.15`, approved employee CIDR `172.20.8.0/22`, sing-box TCP `18443`, loopback-only telecom proxy `127.0.0.1:8080`.
- Elevated/OS/VM/listener owner/actual HTTPS-over-proxy/hash/manifest/`sing-box check` gates before `ShouldProcess` and before persistent mutation.
- One `SupportsShouldProcess`; `-WhatIf` executes all preflight checks and makes zero persistent changes.
- Atomic create-new baseline evidence before system mutation, with services, listeners, routes, firewall rules and filters, 8080 owner, input hashes, config hash, and CONNECT result.
- External write-ahead journal is atomically published beside the explicit baseline before the first Program Files/ProgramData/service/firewall mutation; both owned roots carry transaction-ID owner markers.
- ACL-hardened Program Files binaries and ProgramData config/runtime-manifest paths, installed-file rehash, exact service and three exact firewall resources.
- Transaction-ID ownership descriptions, reverse compensation, rollback of exact owned resources only, immutable paths, literal-path removal only, and final staging cleanup.
- Compensation removes firewall rules in reverse order, then proves the service absent before deleting backing files. Rollback retains its external journal until exact absence is proven and returns `AlreadyRolledBack` on safe retries.
- Preflight rejects effective existing inbound allows that could expose TCP 18443 beyond `172.20.8.0/22`; baseline service inventory hashes rather than records service command lines.
- Preflight also rejects any existing TCP 18443 listener so the SCM host's loopback readiness probe cannot be satisfied by an unrelated process. The TCP 8080 block is scoped to local address `172.20.9.15`, so it blocks LAN access without matching the required `127.0.0.1:8080` telecom flow.
- Because sing-box 1.13.19 does not implement the Windows SCM control handler, the approved brief was necessarily expanded with `cmd/overseas-server-service`. This first-party host uses `golang.org/x/sys/windows/svc`, reads only fixed ProgramData config/manifest paths, delegates direct no-shell launch to the existing kill-on-close supervisor, invokes `coreverify.Verify` in the supervisor's immediate pre-launch boundary, reports `Running` only after local TCP 18443 readiness, and treats unproven Stop/Shutdown cleanup as a service failure.
- The offline packaging target builds `overseas-server-service.exe`, copies and rehashes it into the pinned sing-box bundle, and atomically records `server_service_sha256`. Install requires that manifest hash and a caller-explicit `ExpectedServerServiceSha256`, rehashes after installation, and registers SCM with the quoted service-host path only. Neither SCM argv nor sing-box argv contains secret material.
- Native `sing-box check` and `icacls.exe` calls immediately capture both `$?` and `$LASTEXITCODE`; config contents/secrets are never placed in argv or parameters.
- Both owned roots have inheritance removed, Administrators/SYSTEM-only access, and an explicit Administrators owner before binaries/configuration are published, matching `coreverify`'s runtime ownership requirements.

## Fresh Verification

- Windows PowerShell 5.1 / Pester 3.4 full suite: 68 passed, 0 failed.
- PowerShell 7 full suite: 68 passed, 0 failed.
- Portable Go 1.27.0: `go test ./...` passed.
- Portable Go 1.27.0: `go vet ./...` passed.
- Portable Go 1.27.0: `go build -trimpath ./cmd/overseas-server-service` passed.
- `git diff --check` passed.

## Concerns / Operational Boundaries

- Unit tests mock all Windows service/network/firewall commands; no live VM install or rollback was attempted by design.
- No live SCM integration, service install/start, firewall mutation, or rollback was attempted. The Go handler/supervisor lifecycle and PowerShell preflight/WhatIf paths are unit-tested with fakes/mocks, so a controlled VM rehearsal remains required before production use.
- High-risk preflight refusals execute behaviorally, but the PowerShell compensation/rollback ownership matrix is still primarily protected by static ordering/ownership contracts rather than a full injected-failure matrix. A controlled VM rehearsal should include partial install and repeated rollback checkpoints.
- Operators must run `package-server-service` after acquiring the pinned `bin/sing-box` bundle, then supply the resulting `server_service_sha256` explicitly to Install; the installer fails closed if either pin is missing or differs.
- The CONNECT proof uses a fixed HTTPS HEAD request through `127.0.0.1:8080`; controlled deployment still depends on that approved probe destination being reachable through the telecom session.
- Install intentionally refuses pre-existing exact service/firewall/install/data resources rather than guessing ownership. Operators must use the recorded transaction rollback or resolve the collision explicitly.

## Review Follow-up — 2026-08-29

- RED reproduced four failures: the management-rule helper was absent, CIM multi-value `LocalPort` arrays were missed, a broad multi-port allow reached `-WhatIf`, and the empty-unmarked directory bypass deleted a root whose owner marker was never published.
- `ManagementPorts` is now the real string array `@('22', '3389', '5985', '5986')`. A behavioral Pester test executes the production rule helper through the PS5.1/PS7 `New-NetFirewallRule` proxy and proves four distinct `LocalPort` values are received.
- `Test-PortSpecificationIncludes` now iterates `@($Specification)` and parses every element for exact ports, ranges, comma-separated entries, and `Any`. Behavioral preflight covers a CIM-style `@('443', '18443')` broad allow and refuses it.
- `AllowEmptyUnmarked` was removed from the function and every compensation/rollback caller. A partial-publication test proves an empty root created before `owner.json` remains untouched, while a correctly marked root with the exact transaction ID is removable.
- GREEN verification: focused server suite 20/20 in both PowerShell engines; full suites 68/68 in both; portable Go test/vet and the first-party server-service build passed; `git diff --check` passed.
## 2026-08-31 PoC telecom wildcard-listener compatibility

The operator explicitly accepted remote reachability of the telecom client's
TCP 8080 listener for this PoC. The server installer now accepts exactly one
listener on `127.0.0.1`, `::1`, `0.0.0.0`, or `::`, while retaining the live
PID, executable path, SHA-256, valid Authenticode signature, and successful
HTTPS CONNECT proofs. The product no longer creates, owns, reports, or rolls
back `RegenBioOverseasAccess-Block8080-Remote`; its canonical firewall set is
the employee-scoped TCP 18443 allow and management-port protection rules.

TDD evidence:

- RED: Windows PowerShell focused server suite produced 18 passed / 2 failed
  for the old fixed 8080 rule and loopback-only rejection.
- GREEN: focused server suite produced 20/20 under Windows PowerShell 5.1 and
  20/20 under PowerShell 7.
- Full regression: locked Go `test -count=1 ./...` and `vet ./...` passed;
  full Pester produced 115/115 under both Windows PowerShell 5.1 and
  PowerShell 7.

Accepted risk: an internal device may connect directly to VM101 TCP 8080 and
bypass the product's TCP 18443 authorization boundary. This exception is for
the PoC and requires a fresh production decision.

Live VM101 `-WhatIf` exposed two Windows PowerShell 5.1 compatibility gaps.
The installer now preloads discovery modules and runs its read-only input
verification with the global AllScope WhatIf preference disabled inside a
`try/finally`, restoring it before any mutation boundary. Listener discovery
reads the listener set and filters ports in memory, avoiding the VM build's
ObjectNotFound behavior for an unused `-LocalPort`. A packaged-app firewall
allow with a nonempty Package SID is no longer treated as applying to the
desktop sing-box executable. Real VM101 WhatIf then passed with no evidence,
service, listener, file, or firewall mutation. Fresh post-fix regression:
locked Go test/vet passed and both full Pester engines passed 117/117.

---

## 2026-09-07 cross-platform Task 7 Windows Flutter integration (new task; checkpoint)

This section is independent of the historical Task 7 report above. Implementer base: `5d78c00`; parent documentation commits were made concurrently. Worktree: `C:/Users/Eleme/codex_workspace/overseas-access-gateway/.worktrees/cross-platform`. Code is scoped to `apps/regen_access`; no backend or production-network changes.

### Implemented

- Windows-only MethodChannel AccessClient selects the real native bridge in main; injectable fakes and unsupported-platform unavailable fallback remain.
- Native bridge permits only status/connect/disconnect/probe and 32-hex request IDs, constructs APIv1 newline frames itself, and connects only `\\.\pipe\RegenBioOverseasAccess`. Test endpoint injection exists only under the standalone `REGEN_NATIVE_TEST` build definition. Maximum response is 64 KiB; partial reads are assembled; incomplete/oversized frames are rejected. SQOS identification prevents the pipe server impersonating the GUI at a stronger level.
- One background worker and at most three outstanding requests; platform results return on the window thread. Shutdown signals the worker, cancels pending overlapped I/O, waits for OS completion before destroying OVERLAPPED storage, joins, drains posted notifications without raw object pointers, then destroys results before the Flutter engine. GUI exit does not send disconnect or stop the service.
- Dart validates response identity/version/framing, approved status/error fields, probe target/latency/status/error/timestamp/generation, including RFC3339 shape and zero timestamps. Observation budgets remain 130/100/10/8 seconds. Native I/O timeout is classified conservatively: a definite pre-dispatch failure may release ownership; after possible dispatch, a transport loss or invalid reply becomes OperationUncertainException. Page and tray remain lifecycle-locked for this GUI session even after a fresh terminal status. Read-only refresh continues.
- Page and tray use one action owner. Tray includes current state/brief current-generation latency, home/details navigation within one window, lifecycle label, per-user UI startup, and “退出应用”. Opening, hiding, navigating, startup and exit never connect or disconnect. A locally drawn app-owned R mark replaces the tray/window scaffold icon. First hide shows one notification per GUI session; TaskbarCreated re-adds the icon.
- A session-local named mutex prevents duplicate GUIs and the second launch focuses the first. Close hides, minimize remains in taskbar, UI uses asInvoker manifest.
- Confirmed the default native caption has a visible disabled maximize slot. Parent explicitly authorized a focused native_caption implementation: Windows nonclient geometry remains, custom paint/hit regions expose only minimize and close, retain caption dragging/system-menu/Alt+F4 routing, block maximize/resize system commands, provide TITLEBARINFOEX with absent maximize geometry, and scale by window DPI. Flutter content remains 460×540 logical pixels.

### TDD and commands (checkpoint)

Flutter executable: `C:/Users/Eleme/codex_workspace/.tools/flutter-3.47.2/bin/flutter.bat`. Commands run in `apps/regen_access`, with process-scoped `CI=true`.

- RED: `flutter test test/tray_state_test.dart test/access_client_test.dart` failed because TrayState/WindowsAccessClient/OperationUncertainException were not implemented. After implementing, initial focused suite passed 15 tests.
- RED: tray/page integration test failed to compile because WindowsShell/MyApp.shell did not exist. GREEN: tray suite passed 4 tests. An initial asynchronous test awaited an intentionally pending action; fixed the harness to dispatch without awaiting that reply, then verified both page/tray ownership assertions.
- RED: tray latency summary expected “已连接 · 92 ms”, received null. GREEN after adding current-generation-only summary; focused suite passed 17 tests.
- RED: three invalid timestamps (normalized out-of-range month, date-only, Go zero time) incorrectly produced Status. GREEN after strict parsing: focused suite passed 20 tests.
- Native RED: `cmake -S windows/runner/tests -B build/native-tests` / `cmake --build build/native-tests --config Release` failed for missing access_bridge.cpp before implementation; later failed for missing native_caption.cpp before caption implementation. Native initial tests passed, then were extended for shutdown and caption behavior.
- GREEN full suite: `flutter test` -> **74 tests passed**, including unchanged golden pages and lifecycle ownership regressions.
- GREEN focused final: `flutter test test/access_client_test.dart test/tray_state_test.dart` -> **20 tests passed**.
- `flutter analyze` initially found style-only missing-braces lints; these were corrected. Subsequent run -> **No issues found**; final checkpoint repeat is pending output collection.
- `flutter build windows --release` -> success before and after custom caption, output `build/windows/x64/runner/Release/regen_access.exe` (latest caption build 23.7s).
- Native tool: `C:/Program Files (x86)/Microsoft Visual Studio/2022/BuildTools/Common7/IDE/CommonExtensions/Microsoft/CMake/CMake/bin/cmake.exe`; build standalone target then `build/native-tests/Release/native_shell_test.exe` -> **34 actual assertions passed** (dynamic count). Earlier hardcoded “16/23 assertions” summaries described test groups; final dynamic count is authoritative. Covers exact emitted request frame, isolated fake byte-mode pipe fragmentation/oversize/missing newline/timeout, pre-dispatch failures, unsupported action/id rejection, stop-event cancellation while awaiting a reply, owned window hide/focus/minimize/TaskbarCreated handling, absent maximize slot and min/close hit rectangles.
- Actual owned release smoke: `windows/runner/tests/smoke-owned-window.ps1 -Executable build/windows/x64/runner/Release/regen_access.exe` -> PASS. Native caption state min=0, max=32769 (INVISIBLE|UNAVAILABLE), close=0; maximize bounds=0,0. Actual client **460×540 logical at DPI96**; native caption close click hides; second process exits and restores first; native caption minimize click minimizes; a single tray-select message restores; GUI exit terminates its own process within five seconds. Only read-only automatic service status traffic was permitted. All test-started app processes were closed.
- `git diff --check` passed (only repository CRLF normalization warnings).

### Actual versus pending native acceptance

Actual: compilation, isolated pipe tests, current-monitor DPI96 logical sizing, native titlebar hit/visibility geometry, actual caption button dispatch, close/restore, duplicate startup, minimize, synthetic single tray select, synthetic TaskbarCreated, clean owned process exit.

Pending: human visual appearance acceptance of the custom nonclient caption, actual multi-monitor/mixed DPI movement and accessibility assistive-technology behavior, actual Explorer restart recovery, actual right-click menu interaction and one-time notification appearance, and per-user login/reboot startup lifecycle. Explorer was not restarted and the user's startup registry was not toggled. Synthetic TaskbarCreated is not evidence of an actual Explorer restart.

Screenshot attempts were invalid: PrintWindow produced black pixels; foreground-checked screen capture returned unrelated compositor content. The exact task-created PNG was deleted, capture code was removed from the test script, and no screenshot is supplied or claimed as visual evidence.

Architecture limitation explicitly agreed with parent: APIv1 has no request-ID operation lookup. Uncertain lifecycle remains locked in the current GUI session; a new GUI performs a fresh status read and represents a new explicit user intent, not proof the prior operation was cancelled. Controller serialization/coalescing remains authoritative. No persistent uncertainty registry/operation database was added. Native worker queue/engine lifetime is code-reviewed plus owned process smoke; no instrumented engine destruction race stress suite is claimed.

### Files / checkpoint status

New: lib/api/windows_shell.dart, lib/model/tray_state.dart, test/access_client_test.dart, test/tray_state_test.dart, windows/runner/access_bridge.{h,cpp}, tray_controller.{h,cpp}, native_caption.{h,cpp}, tests/CMakeLists.txt, tests/native_shell_test.cpp, tests/smoke-owned-window.ps1.

Modified: lib/api/access_client.dart, lib/model/status.dart, lib/main.dart, lib/app.dart, windows/runner/flutter_window.{h,cpp}, main.cpp, win32_window.cpp, runner.exe.manifest, CMakeLists.txt.

Checkpoint: implementation and tests above complete; final self-review, last analyzer result, and scoped commit/SHA to append below. No task commit yet.

### Final self-review before commit

- Final analyzer repeat completed: **No issues found (6.0s)**. Final focused Flutter repeat: **20/20**. The full **74/74** run remains applicable; subsequent production edits were native caption integration and Dart comment/style-only cleanup. Latest native suite dynamically counted **34 passed assertions**.
- Final owned-release smoke also clicks the actual custom caption regions (WM_NCHITTEST → nonclient press → release), rather than calling ShowWindow to stand in for caption clicks: close hides and minimize enters iconic state. It verifies maximize state32769 with empty bounds, current client460×540 at96DPI, duplicate activation, single tray select restoration, and GUI process exit. No owned release processes remain.
- Reviewed worker/method-result ownership, event/OVERLAPPED lifetime, bounded queue, payload restrictions, session uncertainty propagation, startup command quoting, tray deletion/re-add, menu exit ordering, native caption geometry/hit testing, and preservation of approved Flutter pages. Exit posts a private GUI message rather than destroying the tray object while its menu handler is still executing.
- No additional blocker found in reviewed scope. Remaining concerns are the explicit manual acceptance and protocol-correlation limits above, not silently accepted test results. Native caption accessibility exposes titlebar geometry and retains system commands, but assistive-technology validation has not been performed. No claim of actual tunnel/network acceptance is made by this UI task.
