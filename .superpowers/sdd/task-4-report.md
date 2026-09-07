# Task 4 Report — Secret Storage and Fail-Closed Process Supervisor

Date: 2026-08-28

Base commit: `f47ddd922494f5db2359d3b355139b8276b7e636`

Implementation commit message: `feat: protect credentials and supervise sing-box`. The exact hash is reported in the handoff because this report is part of that commit.

## Status

Task 4 is implemented in the assigned `windows-forwarding-poc` worktree. No real network configuration, remote host, VM, route, DNS, adapter, firewall, or service mutation was performed. Process tests launch only the repository's deterministic `fakeconnect` helper in temporary directories.

## Implementation

### Machine-scoped secret storage

- Added Windows-only `secret.StoreMachine` and `secret.LoadMachine` backed by `CryptProtectData` / `CryptUnprotectData`.
- `StoreMachine` uses `CRYPTPROTECT_LOCAL_MACHINE` and optional entropy fixed to `RegenBio/OverseasAccess/v1`.
- The input plaintext slice is zeroed on every return path. DPAPI ciphertext and entropy working buffers are also zeroed after use; DPAPI output memory is zeroed before `LocalFree`.
- Writes use a cryptographically random create-new temporary file in the destination directory, flush and close it, then use Windows replace-existing rename semantics.
- The temporary file receives the protected DACL at creation time, avoiding a permissive create-then-tighten window. The DACL is `D:P(A;;FA;;;SY)(A;;FA;;;BA)`: protected, full control for SYSTEM and Builtin Administrators only.
- Read, DPAPI, and write errors contain operation context but never plaintext or ciphertext content. Missing-file identity remains available through `errors.Is(err, os.ErrNotExist)`.
- The non-Windows implementation returns `ErrUnsupported`; its store stub still zeroes the caller's plaintext buffer.

### Windows process supervision

- Added single-use `supervisor.Process` with the required `Start`, `Ready`, `Stop`, and `Wait` methods.
- `Start` rejects relative, non-canonical, missing, non-regular, symlink, and other reparse-point executable/config paths.
- The executable is invoked directly with exactly `run -c <absolute-config>`; no shell is involved.
- The supervisor creates a Windows job object with `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`, assigns the child, and uses a new process group for graceful control-break signaling.
- `Ready` supports a deterministic injected local probe for unit/integration use. With no injected probe, it reads the sing-box TUN `interface_name` from the absolute config and probes local interface presence.
- Readiness timeout terminates the complete job before returning `ErrReadyTimeout`.
- Unexpected exits return typed `*supervisor.ExitError` with only exit code and before-ready state; command line, config, and log content are not included.
- `Stop` first requests graceful shutdown via `CTRL_BREAK_EVENT`, then terminates the job after the configured grace period. Repeated controlled stops are idempotent.
- Stdout and stderr share a concurrency-safe streaming redactor that handles secrets split across writes and bounds emitted log bytes. Configured values are replaced with `[REDACTED]`.
- The non-Windows process implementation exposes the same portable shape and returns `ErrUnsupported`.

### Deterministic helper

- Added `tests/integration/fakeconnect/main.go`.
- It accepts only `run -c <absolute-config>` and supports the required `ready`, `exit-before-ready`, `hang-on-stop`, and `write-secret` modes.
- The hang mode can spawn a descendant so job-object tree termination is tested against a real Windows child process.

## RED → GREEN evidence

### Secret RED

After adding the Windows DPAPI contract tests first:

```powershell
C:\Users\Eleme\codex_workspace\.tools\go1.27.0\go\bin\go.exe test ./internal/secret
```

Result: FAIL as expected. The compiler reported `undefined: StoreMachine`, `undefined: LoadMachine`, and `undefined: zero` because the package implementation did not yet exist.

### Secret GREEN

After implementing DPAPI, secure temporary-file creation, atomic replacement, and stubs:

```powershell
C:\Users\Eleme\codex_workspace\.tools\go1.27.0\go\bin\go.exe test ./internal/secret
```

Result: PASS. Covered same-machine round trip, corrupt ciphertext, missing file identity, replacement/no leaked temporary file, DACL inspection, regular-file mode, and caller plaintext zeroing.

### Supervisor RED

After adding the process lifecycle tests and the test helper first:

```powershell
C:\Users\Eleme\codex_workspace\.tools\go1.27.0\go\bin\go.exe test ./internal/supervisor
```

Result: FAIL as expected. The compiler reported missing `Process`, `ErrReadyTimeout`, `ExitError`, `ErrAlreadyStarted`, and `ErrUnsafePath`.

### Supervisor GREEN

After implementing Windows process/job supervision and portable stubs:

```powershell
C:\Users\Eleme\codex_workspace\.tools\go1.27.0\go\bin\go.exe test -v ./internal/supervisor
```

Result: PASS. Covered readiness timeout termination, typed exit-before-ready failure, graceful-timeout escalation, descendant job termination, idempotent stop, bounded secret-redacted logs, second-start rejection, and absolute regular path enforcement.

The escalation test deliberately registers a control-break handler in `fakeconnect`, proves `Stop` waits through the grace interval, and then waits for the descendant process handle to enter the signaled state after job termination.

## Verification

Required focused gate:

```powershell
C:\Users\Eleme\codex_workspace\.tools\go1.27.0\go\bin\go.exe test ./internal/secret ./internal/supervisor ./tests/integration/fakeconnect
```

Result: PASS.

Full Go regression:

```powershell
C:\Users\Eleme\codex_workspace\.tools\go1.27.0\go\bin\go.exe test ./...
```

Result: PASS for all existing and new packages.

Lifecycle repetition:

```powershell
C:\Users\Eleme\codex_workspace\.tools\go1.27.0\go\bin\go.exe test -count=10 ./internal/secret ./internal/supervisor
```

Result: PASS for all 10 repetitions.

Static analysis:

```powershell
C:\Users\Eleme\codex_workspace\.tools\go1.27.0\go\bin\go.exe vet ./...
```

Result: PASS.

Non-Windows compile gate:

```powershell
$env:GOOS='linux'
$env:GOARCH='amd64'
go test -c ./internal/secret
go test -c ./internal/supervisor
go build ./tests/integration/fakeconnect
```

Result: PASS. Temporary cross-build artifacts were removed after verification.

Source gate:

```powershell
git diff --cached --check
```

Result before commit: PASS.

## Self-review

- Confirmed DPAPI machine scope and exact entropy binding.
- Confirmed the restrictive DACL is supplied to `CreateFile` at creation, not applied after plaintext-derived data is written.
- Confirmed all caller-provided plaintext and intermediate buffers are zeroed where Go/Windows ownership permits.
- Confirmed no error path formats plaintext, ciphertext, configured secrets, config contents, or child output.
- Confirmed process invocation uses `CreateProcessW` with a composed `exe run -c <absolute-config>` command line and never a shell.
- Confirmed job assignment, graceful timeout, whole-tree termination, and descendant death against real Windows processes.
- Confirmed redaction is streaming-safe across write boundaries and output is capped.
- Confirmed Task 1–3 and the old PoC regression suite remain green.

## Remaining concerns / integration obligations

1. `Process.Start` now requires a non-nil `VerifyExecutable` capability and invokes it inside the native launch boundary immediately before `CreateProcessW`. Task 5 must supply a closure backed by the existing `internal/coreverify.Verify`; no alternate unverified launch path is permitted.
2. `go test -race` could not run with the portable toolchain because it reports `-race requires cgo; enable cgo by setting CGO_ENABLED=1`, and this environment has no configured C compiler. Focused tests, 10 lifecycle repetitions, full regression, vet, and cross-compilation all pass; race instrumentation remains an external verification item.

## Commit

```text
feat: protect credentials and supervise sing-box
```

The exact commit hash is reported in the handoff because this report is included in the commit itself.

## Security review remediation

The first Task 4 security review failed on four related lifecycle boundaries: execution before job assignment, unenforced binary verification, cleanup errors that were discarded/unconfirmed, and a readiness probe that could ignore context and block teardown. All review findings were reproduced with RED tests before production changes.

### RED evidence

Verifier enforcement RED:

```text
undefined: ErrVerifierRequired
unknown field VerifyExecutable in struct literal of type Process
```

Suspended-launch/escape RED:

```text
undefined: defaultProcessOps
unknown field ops in struct literal of type Process
```

Blocked-probe RED:

```text
TestReadyTimeoutIsBoundedWhenProbeIgnoresContext:
Ready blocked on a context-ignoring probe
```

Typed cleanup RED:

```text
undefined: CleanupError
```

Tree-confirmation RED:

```text
ops.waitJobEmpty undefined
```

Stop fallback RED:

```text
TestStopReportsTerminateFailureAfterCloseFallback:
Stop did not use close fallback after terminate failure
```

Resume-fallback and descendant-log RED:

```text
TestResumeCleanupClosesJobBeforeWaitWhenTerminateFails:
cleanup order = "terminate,wait,close", want terminate,close,wait

TestUnexpectedExitClosesJobBeforeWaitingForDescendantLogs:
unexpected-exit handling waited on descendant-held logs before closing the job
```

Immediate verification-boundary RED:

```text
cannot use func(..., verify func(string) error) as the old launchSuspended signature
too many arguments in call to realLaunch
```

### Remediation implemented

- Replaced `exec.Cmd.Start` plus post-launch assignment with direct `CreateProcessW` using `CREATE_SUSPENDED`, `CREATE_NEW_PROCESS_GROUP`, and an explicit inherited-handle list.
- Retain the primary process/thread handles, assign the still-suspended root to the kill-on-close job, and resume only after assignment succeeds.
- Assignment failure terminates the still-suspended root; resume failure terminates the assigned job. If job termination fails, cleanup closes the kill-on-close job before waiting.
- Added `escape-immediately` and `exit-with-descendant` helper modes. Tests prove assign/resume failures cannot run root or descendant code and that an inherited log handle cannot delay job closure.
- Added mandatory `Process.VerifyExecutable`. The verifier is passed into the native launch primitive and called after pipe/attribute/command preparation, immediately before `CreateProcessW`.
- Added bounded asynchronous probe execution, so even a probe that ignores its context cannot prevent readiness timeout and teardown.
- Added typed `CleanupError` joined with `ErrReadyTimeout` or context errors. Terminate, job-close, root-wait, and job-empty confirmation errors remain discoverable through `errors.Is`/`errors.As`.
- Readiness teardown takes ownership of the job handle, uses close-on-terminate-failure fallback, waits for the root, queries `JobObjectBasicAccountingInformation` until `ActiveProcesses == 0`, and then closes the job handle.
- Later `Stop` calls wait on a bounded cleanup-completion channel and return the recorded cleanup failure rather than blocking on stale `stopping` state.
- Unexpected root exit closes the job before waiting for log EOF, preventing a descendant from pinning supervisor completion with inherited stdout/stderr.

### Security-review verification

Focused gate:

```powershell
C:\Users\Eleme\codex_workspace\.tools\go1.27.0\go\bin\go.exe test -count=1 ./internal/secret ./internal/supervisor ./tests/integration/fakeconnect
```

Result: PASS (`internal/secret` 0.054s, `internal/supervisor` 3.212s, helper builds).

Lifecycle repetition:

```powershell
C:\Users\Eleme\codex_workspace\.tools\go1.27.0\go\bin\go.exe test -count=10 ./internal/supervisor
```

Result: PASS in 15.267s.

Full regression:

```powershell
C:\Users\Eleme\codex_workspace\.tools\go1.27.0\go\bin\go.exe test -count=1 ./...
```

Result: PASS for every package; `internal/supervisor` completed in 2.321s.

Static analysis:

```powershell
C:\Users\Eleme\codex_workspace\.tools\go1.27.0\go\bin\go.exe vet ./...
```

Result: PASS after changing the test helper to avoid copying a `Process` containing `sync.Mutex`.

Non-Windows compile gate:

```powershell
$env:GOOS='linux'
$env:GOARCH='amd64'
go test -c ./internal/secret
go test -c ./internal/supervisor
go build ./tests/integration/fakeconnect
```

Result: PASS; generated cross-build artifacts were removed.

Race instrumentation was retried with `CGO_ENABLED=1`:

```text
cgo: C compiler "gcc" not found: exec: "gcc": executable file not found in %PATH%
```

Race instrumentation therefore remains unavailable in this workstation toolchain; all other requested gates pass.

## Second security re-review remediation

The second review identified two terminal-state races: graceful root exit published
`done` without job-tree confirmation and allowed `Stop` to discard cleanup failures;
and `Wait` captured `cleanupDone` before blocking, so cleanup beginning during the
root transition could be missed. Both were reproduced before production changes.

### RED evidence

Focused RED command:

```powershell
C:\Users\Eleme\codex_workspace\.tools\go1.27.0\go\bin\go.exe test -timeout 30s -run 'TestGracefulStopReports|TestWaitObservesCleanupStartedAfterWaitBlocks' -v ./internal/supervisor
```

Result: FAIL, with the intended three failures:

```text
TestGracefulStopReportsJobCloseFailureAndKillsDescendant:
Stop error = <nil> <nil>, want typed close-job failure

TestGracefulStopReportsJobTreeConfirmationFailure:
Stop error = <nil> <nil>, want typed job-empty failure

TestWaitObservesCleanupStartedAfterWaitBlocks:
Wait returned before in-flight cleanup completed: <nil>
```

### Remediation implemented

- Added one mutex-protected cleanup ownership transition shared by readiness
  failure, forced stop, graceful root exit, and unexpected root exit. Exactly one
  path removes and closes the job handle; all other terminal paths wait for its
  result.
- Graceful/unexpected root exit now terminates remaining job members, positively
  waits for `ActiveProcesses == 0`, closes the job, and records failures as a
  typed `CleanupError`.
- `done` is now the final terminal barrier. The wait loop publishes it only after
  job cleanup, descendant/log closure, and process-handle cleanup have finished.
  `Wait` therefore cannot snapshot and miss cleanup that starts during exit.
- Every `Stop` root-exit branch returns the final joined `waitErr`/`cleanupErr`.
  A failed teardown still lets later `Stop` calls return the recorded cleanup
  failure instead of waiting forever on an unreachable terminal state.
- Added an immediate `rootExited` transition so readiness cannot report success
  during the interval between root death and completed tree cleanup.
- Added a real graceful helper mode whose root honors CTRL_BREAK while a
  descendant remains alive. Failure-injection tests cover job close, job-empty
  confirmation, descendant death, and a waiter already blocked before cleanup
  begins.

### GREEN evidence

Focused GREEN command:

```powershell
C:\Users\Eleme\codex_workspace\.tools\go1.27.0\go\bin\go.exe test -timeout 45s -run 'TestGracefulStopReports|TestWaitObservesCleanupStartedAfterWaitBlocks' -v ./internal/supervisor
```

Result: PASS; all three tests passed in 2.083s.

Complete supervisor lifecycle gate:

```powershell
C:\Users\Eleme\codex_workspace\.tools\go1.27.0\go\bin\go.exe test -timeout 120s -v ./internal/supervisor
```

Result: PASS; all 22 supervisor tests passed in 2.548s.

Lifecycle repetition:

```powershell
C:\Users\Eleme\codex_workspace\.tools\go1.27.0\go\bin\go.exe test -timeout 180s -count=10 ./internal/supervisor
```

Result: PASS in 18.344s.

Full regression:

```powershell
C:\Users\Eleme\codex_workspace\.tools\go1.27.0\go\bin\go.exe test -timeout 180s ./...
```

Result: PASS for every package; `internal/supervisor` completed in 3.622s.

Static analysis:

```powershell
C:\Users\Eleme\codex_workspace\.tools\go1.27.0\go\bin\go.exe vet ./...
```

Result: PASS.

Non-Windows compile gate:

```powershell
$env:GOOS='linux'
$env:GOARCH='amd64'
go test -c -o .superpowers/sdd/task4-secret-linux.test ./internal/secret
go test -c -o .superpowers/sdd/task4-supervisor-linux.test ./internal/supervisor
go build -o .superpowers/sdd/task4-fakeconnect-linux ./tests/integration/fakeconnect
```

Result: PASS; all three Linux/amd64 artifacts were produced and then removed.

Race instrumentation remains unavailable for the already documented workstation
toolchain reason (`gcc` is absent). No new concern was found in this remediation.

---

## Cross-platform plan Task 4 — temporary administrator diagnostics (2026-09-07)

This section is the current Task 4 implementation report; the historical secret-storage/supervisor report above is preserved.

Implementation base: `76d252b`; parent plan-only commit `aaaea93` arrived during implementation. Worktree: `.worktrees/cross-platform`, branch `feature/cross-platform`. Commit subject: `feat(diagnostics): add expiring admin mode`.

### Implementation

- Added OS-independent `diagnosticmode.Gate`: inert construction/default collection, lazy recorder creation on 15/30/60-minute enable, synchronized automatic timer expiry and access-time expiry, stale-timer protection during renewal, permanent Close, restart disabled. Expiry closes the recorder and drops its event buffer. Recorder limits remain 2 MiB per file / five files; existing truncation, retention and redaction rules are reused.
- Wired the Windows service/controller/network sink and legacy trace source through the same gate. Network recovery snapshots and process/network transaction interfaces are unchanged. Existing concise startup stderr notices remain; these are not persistent diagnostic collection.
- Child output uses independently framed stdout/stderr streams, bounded complete lines, existing trace redaction, and drops oversized/incomplete lines. Disabled bytes are never buffered: only a boundary bit is retained, so `off: password=; enable; secret\\n` drops the suffix. Expiry clears pending lines and prevents suffix replay. The service disables the supervisor's separate lifetime diagnostic tail; ordinary supervisor users retain their original tail/prefix behavior. Native launch now supplies two output pipes and joins/closes both before log completion. Completed per-stream writers unregister from the gate.
- Added v1 `diagnostic-enable` handling, authenticating the accepted pipe **after** request read/decode. Authorization queries the impersonated thread token's enabled Builtin Administrators membership; JSON administrator fields have no authority. Missing handles, anonymous tokens, failed token checks, and deny-only membership reject.
- Impersonation runs on a dedicated locked goroutine. Token is closed before RevertToSelf; revert failure rejects and exits without unlocking so Go terminates the contaminated OS thread, leaving service recovery available. Verified the installed Go 1.27 runtime's documented guarantee at `src/runtime/proc.go:5658` onward. Actual OS revert failure was not induced.
- Added Windows administrator client dial using `PipeImpLevelIdentification` and minimal `regen-access diagnostic-enable <15|30|60>` CLI with a five-second bound. No GUI entry, new disable API, account/enrollment/update controls, or deployment changes.

### TDD evidence

All commands used `C:/Users/Eleme/codex_workspace/.tools/go1.27.0/go/bin/go.exe` in this worktree.

1. RED: `go test ./internal/diagnosticmode ./internal/traceevent` failed because new Gate/New/timer types were missing; traceevent passed. GREEN: same packages `-count=1` passed after gate implementation.
2. RED: `go test ./internal/traceevent -run TestRecorderCloseReleasesMemory -count=1` failed `closed recorder retained diagnostics`. GREEN: recorder Close now clears events; traceevent + gate passed. Existing truncation test captures the batch before Close to match the new release semantics.
3. RED: `go test ./internal/agent -run TestDiagnosticEnable -count=1` failed on missing `WithDiagnosticMode`. GREEN: real random local pipe tests passed: actual elevated admin identification succeeds, anonymous rejects despite JSON administrator=true, non-pipe transport rejects. A later distinct restricted-token test passed with Administrators SID deny-only plus identification, proving denial is not just anonymous-client rejection. During test setup, a fake controller missing its diagnostic state and CreateRestrictedToken's rejection of a pseudo token were corrected; these were fixture errors, not feature RED evidence.
4. RED: `go test ./internal/clientapi ./cmd/regen-access -run TestDiagnostic -count=1` failed on missing admin dial/method and CLI run. GREEN: duration validation, admin dial selection, request shape and CLI exit handling passed. A separate random-pipe test exercises the actual default administrator dial and successfully opens its identification token.
5. RED: service diagnostic wiring test failed on missing `newServiceDiagnostics`, `diagnostics`, `newProcess`. Supervisor test failed on missing `DisableDiagnosticTail`/`configureOutput`. GREEN: focused service/supervisor tests passed, including disabled disk inactivity, enable/redaction, expiry and fresh output only after re-enable.
6. RED: gate independent-stream test failed on missing `NewOutputStream`; native output test failed `got 0 output streams`. GREEN: independent streams, disabled/expired partial-line boundaries, native two-stream redaction and close-after-stop passed. Readiness-timeout cleanup of both streams also passed.

### Final verification

- Focused: `go test ./internal/diagnosticmode ./internal/traceevent ./internal/agent ./internal/clientapi ./internal/supervisor ./cmd/overseas-agent ./cmd/regen-access -count=1` — PASS, all seven packages.
- Additional native/default-client coverage: `go test ./internal/clientapi ./internal/supervisor -run 'TestDefaultAdministrator|TestNativeOutput' -count=1` — PASS.
- Full required suite, run once after code completion: `go test ./... -count=1` — PASS, 31 packages with tests; fakeconnect has no tests. Includes process termination/descendant cleanup, recovery, existing retention/file limits and credential redaction.
- `git diff --check` — PASS (only repository LF→CRLF advisory messages).
- `GOOS=linux GOARCH=amd64 go build ./internal/diagnosticmode` — PASS, shared gate has no Windows dependency.
- Attempted `GOOS=linux GOARCH=amd64 go build ./internal/diagnosticmode ./cmd/regen-access` — blocked by existing `internal/agent` shared files referencing `WindowsNodeRouteSnapshot`, `windowsTUNInterface`, and Windows firewall rule constants. Left for platform adapter/CLI Tasks 5/9; the current CLI is usable on Windows. No Linux runtime claim.
- Race instrumentation was not run: `Get-Command gcc` found no compiler, consistent with the historical workstation limitation.

### Changed files

- `internal/diagnosticmode/gate.go`, `gate_test.go`
- `internal/traceevent/recorder.go`, `recorder_test.go`
- `internal/agent/diagnostic_windows.go`, `diagnostic_windows_test.go`, `pipe_windows.go`
- `internal/clientapi/client.go`, `client_windows.go`, `client_stub.go`, `diagnostic_test.go`, `diagnostic_windows_test.go`
- `internal/supervisor/process_windows.go`, `diagnostic_windows_test.go`
- `cmd/overseas-agent/main_windows.go`, `diagnostic_windows_test.go`
- `cmd/regen-access/main.go`, `main_test.go`
- this report (append only)

### Scope and concerns

All authorization tests used unique random **local** pipe names and temporary files. Process tests used only the repository fakeconnect helper. No installed fixed service, production network, remote host, VM, firewall, route, DNS, enrollment, credential provisioning, or deployment was touched.

Self-review: added independent stream framing after discovering the existing native shared stdout/stderr handle; verified disabled-period partial lines cannot leak suffixes after enable and both readers finish on stop/readiness failure. Production service does not keep the legacy child tail, so detailed readiness context comes from the enabled recorder rather than an always-present tail. Partial final/oversized child lines are deliberately discarded. Revert-failure quarantine is source-reviewed but not OS fault-injected; race instrumentation and Linux CLI runtime remain unverified as stated above.
