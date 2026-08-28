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
