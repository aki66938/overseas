# macOS Standalone TUN PoC Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox syntax for tracking.

**Goal:** Deliver an actually connected Mac PoC with recoverable network ownership, not the current unavailable-service preview.

**Architecture:** Reuse agent.Controller, LocalHandler, API v1, lineprobe and singconfig. Supply Darwin Unix socket, process and network adapters; connect Flutter through a constrained native IPC bridge. A root LaunchDaemon owns installed immutable binaries/config; GUI runs as the device user.

**Tech Stack:** Go 1.27.0, sing-box 1.13.19, Flutter 3.47.2, Xcode 27 RC, macOS arm64.

## Global Constraints

- Do not alter Windows behavior or the existing untracked Linux supervisor files.
- No Developer ID, no SIP/Gatekeeper disable, no MDM removal, no arbitrary client-supplied executable or shell command.
- Root-owned installation; only root and the installer-selected local owner may control the service. Diagnostics remain administrator-only and default off.
- Persist ownership before mutations; restore on disconnect/failure and service restart; do not delete other software's routes or terminate other VPNs.
- Main page does not report slow sites. Detail list retains eight sites. Browser YouTube is additional verification.
- Tests precede implementation. Compilation is not network acceptance. Preserve failing golden baselines.

### Task 1: Darwin local API transport

Files: create `internal/platform/darwin/socket_darwin.go`, `socket_darwin_test.go`, `internal/clientapi/client_darwin.go`; modify client stub build constraints only where required.

Interfaces: `const SocketPath = "/var/run/regen-access/control.sock"`; `NewSocketServer(handler, ownerUID)`, `Serve(context.Context) error`; `DialSocket(context.Context) (net.Conn,error)`. Handler consumes existing `Dispatch(context.Context,localapi.Request,bool) localapi.Response`.

- [ ] Write Darwin tests for authorized owner/root, unauthorized UID, unsafe/symlink runtime directory, root server peer validation, overlong/truncated frames and cancellation.
- [ ] Run targeted tests on Mac and record RED before implementation.
- [ ] Implement socket parent root:wheel 0755 validation, owner-only socket access (root-owned parent prevents replacement), native peer UID checks in both directions, API frame size/deadlines and bounded concurrency. Existing socket paths fail closed; startup recovery must explicitly verify and remove stale own socket before construction.
- [ ] Preserve shared codec and action timeout contracts. Run focused tests, cross-build client on Darwin and existing Windows client regression. Commit and review.

### Task 2: Darwin process and network lifecycle

Files: `internal/platform/darwin/process_darwin.go`, `network_darwin.go`, `snapshot.go` and corresponding tests; `internal/singconfig/client.go`, `client_test.go`.

Interfaces: implement existing agent.ProcessSupervisor and agent.NetworkManager. Darwin configuration uses a fixed checked utun name; reject conflict before start. Process supervisor owns only its child; launchd kills child process group on service shutdown. Do not claim process-tree proof without checking the implemented ownership boundary.

- [ ] Add RenderClient darwin fixture asserting only intentional platform fields differ; preserve Windows serialized configuration. Run RED, implement Darwin config and GREEN.
- [ ] Add tests for snapshot-before-mutate ordering, automatic/static DNS round trip, changed setting conflict, restore idempotence, failed restoration retaining journal, core exit, cancellation and exclusive session ownership.
- [ ] Implement root-only journal, atomic writes, scoped DNS changes, TUN and route verification, generation-bound monitoring. Inspect sing-box Darwin behavior before relying on automatic route/DNS cleanup.
- [ ] Validate exact pinned sing-box config with `sing-box check`; run native adapter tests and controller regressions. Review before live network mutation.

### Task 3: Service composition and GUI

Files: `cmd/regen-access-service/main_darwin.go`, Darwin service configuration/verification in `internal/platform/darwin`; `apps/regen_access/lib/api/`, `lib/main.dart`, `macos/Runner/` and tests.

- [ ] Test malformed/untrusted installation config and core hash rejection; compose Controller, Scheduler, LocalHandler and socket. On termination disconnect using independent bounded cleanup context.
- [ ] Test Mac client lifecycle and API response validation before wiring ordinary-user GUI to fixed socket. No shell transport or elevation from connection button.
- [ ] Preserve compact B layout, minimal copy, details, eight targets and close/minimize semantics. Configure only entitlements needed for the chosen local IPC route.
- [ ] Run Go and Flutter tests and Mac release build. Keep existing golden mismatch separately documented; do not regenerate it to hide differences.

### Task 4: Package and real-machine acceptance

Files: `scripts/macos/` installer/build/uninstall scripts; `deploy/macos/` launchd configuration and manifest; acceptance report under `docs/acceptance/`.

- [ ] Test install target guards, immutable executable/config permissions, correct owner mapping, upgrade refusal while connected and exact uninstall scope.
- [ ] Produce one PoC package with GUI, service, pinned sing-box, configuration and explicit traffic-CA trust disclosure. No separate manually copied runtime dependencies.
- [ ] Capture actual test Mac DNS/routes/proxy and independent timed rollback before first connect. Verify CLI service first, then GUI; keep SSH reachable and stop on ownership ambiguity.
- [ ] Verify browser Google/YouTube and detail probes; disconnect restoration, reconnect, core crash, then continuous connection >=60 minutes. Sleep/wake requires user interaction and remains unverified until observed.
- [ ] Review whole PoC diff, preserve unrelated files, commit passing work and deliver package path plus exact unverified items.

## Progress

2026-09-10: approved design c83297b; Xcode/Flutter ready. Tasks 1–4 not implemented. Existing preview is not the networking PoC.
