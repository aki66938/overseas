# Task 3 implementation report

## Scope and installation contract

- Fixed root: `/Library/Application Support/RegenBioAccess`, root:wheel 0755.
- `regen-access-service` and `sing-box`: regular non-symlink root-owned 0755.
- `service.json`: regular non-symlink root-owned 0600, <=64 KiB JSON; unknown fields/trailing data rejected. Object keys: `schema_version` (1), `owner_uid` (real non-system account >=501), `core_sha256` (fixed official arm64 1.13.19 digest), `policy` (existing schema 2 approved HTTP CONNECT policy). No executable/config paths accepted.
- `state/`: existing canonical root-owned 0700. Generated `state/sing-box.json` is atomically written 0600 and directory-fsynced.
- `/private/var/run/regen-access`: root:wheel 0755. Persistent daemon.lock 0600 is flocked through startup/recovery/listen/cleanup and never unlinked. Public IPC path remains `/var/run/regen-access/control.sock`.
- Service `--restore` is root-only, fixed-path recovery with exclusive lock, so cannot race an active daemon. Installer/rollback must stop service first. Core ownership recovery runs before network recovery and before listening.

## Implemented behavior

- Composes agent.Controller, 30-second lineprobe scheduler, LocalHandler and Darwin socket. Diagnostics use existing default-off diagnosticmode Gate with existing 15/30/60-minute limits and root peer authority. Service cancellation joins dispatcher work before independent bounded disconnect; no new request may begin during cleanup.
- GUI selects MacAccessClient; WindowsAccessClient remains a compatibility subclass of the same unchanged protocol/lifecycle implementation. Mac transport uses a fixed native socket, validates canonical parent/socket ownership, authenticates getpeereid root, uses nonblocking poll with total action deadlines, capped single-LF frames, and asynchronous Flutter replies. Only sent==0 failures receive pre_dispatch; later failure is uncertain.
- Native menu reflects shared Dart state and includes show/details/connect-or-disconnect/safe exit. Close hides the same 480x224 content window; minimize remains available, maximize/fullscreen disabled. Safe exit disconnects through the shared client then requires a confirmed idle status. Command-Q follows this path. The ordinary GUI never starts shell commands or elevates.
- This internal PoC intentionally removes App Sandbox to access the root daemon Unix socket. Release disables Xcode implicit base entitlement injection; debug JIT remains. No SIP/Gatekeeper change, Developer ID or system extension.
- Parent-authorized integration expansion adds durable core ownership. A fixed service --core-helper receives only inherited fd3 and waits for release. EOF on parent death before durable registration exits without exec. Parent writes/fsyncs root-only owned-core.json with boot UUID/PID/start time/pinned hash before release. Helper revalidates fixed core/config then execs in the same PID/process group. Normal stop deletes the record only after process-group cleanup proof. Restart checks boot/start identity/PGID/executable path, kills only a revalidated owned group, waits for no live members, then removes the record. Different boot never signals old PID/PGID; missing/changed leader with live members fails closed.

## TDD and verification evidence

Native commands were executed by the parent on RB-LT-N40MJH; I read its condensed observed-output record in [mac-task3-native-evidence.md](mac-task3-native-evidence.md). This is not represented as a raw log or as my own remote execution.

- Probe test fixture: prior native RED supplied by parent (`tcp_failed`, Darwin bind 127.0.0.2 Err49). Changed actual source bind to configured 127.0.0.1; separate injected forwarding test asserts 192.0.2.37 is preserved without requiring the address locally. Local `go test ./internal/probe` GREEN. Commit `7423d5e`.
- Parser RED: local `go test ./internal/platform/darwin` undefined ServiceConfig/ParseServiceConfig/PinnedCoreSHA256. GREEN after minimal fixed schema parser.
- Protected files/daemon lock RED: native and cross-compile undefined protectedPath/lockDaemon. Native root fixtures GREEN (safe permissions, symlink/user ownership refusal, duplicate daemon lock refusal, caller-path rejection). Additional binary-content tamper fixture RED undefined verifyCoreFile, GREEN cross-compile and final native root suite.
- Composition gate RED: Darwin cross-compile undefined dispatchGate. GREEN cross-compile after implementation.
- Dart native RED: missing createAccessClient/MacAccessClient, then missing MacShell. Native GREEN: all three targeted tests passed. Full Flutter run: 76 passed, existing 10 golden mismatches retained without baseline regeneration.
- Swift native RED: AccessTransport.swift missing. Native GREEN: standalone -Onone test binary passed framing/whitelist/UID/deadline/error classification plus actual socketpair valid/extra/truncated frame, post-send timeout and actual getpeereid non-root peer rejection tests; final fixture rerun exited 0.
- Native Mac Release build succeeded (39.3 MB); initial codesign verification passed. Parent noticed implicit get-task-allow=true, corrected source Release.xcconfig to CODE_SIGN_INJECT_BASE_ENTITLEMENTS=NO; final Release rebuild succeeded and `codesign --verify --deep --strict` passed with an empty entitlement dictionary (no get-task-allow).
- Durable ownership RED: Darwin cross-compile missing awaitCoreGate/coreOwnership/recoverCore. Native actual parent-death gate EOF test passed. Root persistent record fixture initially failed because Darwin t.TempDir includes a symlink; fixture corrected with EvalSymlinks, production canonical-path validation retained. Final entire native root Darwin platform suite passed, including both successful/durable-failure gate cases, parent death, recovery identity refusal and binary tamper.
- Parent native full Go `go test ./...` passed. Local Windows regression: `go test ./internal/platform/darwin ./internal/agent ./internal/localapi ./internal/singconfig ./internal/probe` passed. `git diff --check` clean (Git reports expected LF/CRLF normalization warnings).

## Self-review and remaining acceptance gates

- Darwin has no pidfd-style atomic identity-and-signal operation here. Recovery rechecks boot/start/PGID/path immediately before its signal, but the narrow post-check PID reuse race is not claimed eliminated. Parent explicitly requested reporting this boundary for review rather than expanding architecture indefinitely. Missing/changed leader never authorizes group-only killing; ambiguous residue retains journal and blocks startup.
- Actual installed-service kill9/restart with the pinned core, ordinary-user GUI-to-root-daemon operation, real network acceptance, safe quit with a real connection, and sleep/wake remain Task4 gates. Fixture subprocesses do not substitute for these.
- No live networking, installer writes or production infrastructure changes performed by this task. Untracked Linux files left untouched. Existing Mac golden baseline unchanged.
