# v16 Observable Debug Console Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Deliver a signed v16 Windows debug client whose service emits complete, redacted connection/recovery traces, whose UI displays them while a connection request is still running, and whose retry path proves old network residue is gone before starting a new generation.

**Architecture:** Add a narrow `internal/traceevent` event store shared by the controller, Windows network manager, PowerShell transport, service lifecycle, Named Pipe server, and Windows UI. The service owns sequence assignment, redaction, bounded memory, and protected JSONL persistence; the pipe exposes only paginated sanitized events. The ViewModel runs independent status and trace loops, renders a single-generation-aware timeline, and implements restore-first safe retry.

**Tech Stack:** Go 1.27.0, Windows service APIs, `go-winio` Named Pipes, `lxn/walk`, PowerShell 5.1/7, Pester, WiX v4, Windows SDK SignTool, existing signed-release scripts.

## Global Constraints

- Work only in `C:\Users\Eleme\codex_workspace\overseas-access-gateway\.worktrees\windows-forwarding-poc` on `feature/windows-forwarding-poc`.
- Use the locked Go binary at `C:\Users\Eleme\codex_workspace\.tools\go1.27.0\go\bin\go.exe` for every Go command.
- Keep the current generation 5 failure and its 23 managed firewall rules untouched until Task 9 records the approved baseline evidence. Do not manually delete rules, routes, adapters, state files, or processes.
- Preserve fail-closed behavior: a failed Connect does not automatically restore the network. Only explicit Disconnect/Recover may release product-owned protection.
- Do not modify VM101, the telecom client, `172.20.9.15:8080`, FlClash, system proxy settings, or unrelated firewall state.
- Never log a PIN, password, proxy authorization value, DPAPI contents, full policy/configuration, PowerShell input envelope, Base64 payload, or complete address collection.
- All new behavior follows RED → minimal GREEN → focused regression → commit. Never combine live deployment with an uncommitted source change.
- Generated `build/`, MSI, extracted package, signature, and evidence files remain untracked.

---

### Task 1: Build the structured trace model, redactor, ring buffer, and JSONL store

**Files:**

- Create: `internal/traceevent/event.go`
- Create: `internal/traceevent/event_test.go`
- Create: `internal/traceevent/redact.go`
- Create: `internal/traceevent/redact_test.go`
- Create: `internal/traceevent/recorder.go`
- Create: `internal/traceevent/recorder_test.go`

**Interfaces:**

```go
package traceevent

const SchemaVersion = 1

type Residue struct {
    ManagedRules  int    `json:"managed_rules"`
    ProductRoutes int    `json:"product_routes"`
    ProductTUNs   int    `json:"product_tuns"`
    CoreProcesses int    `json:"core_processes"`
    Snapshot      bool   `json:"snapshot"`
    SnapshotPhase string `json:"snapshot_phase,omitempty"`
}

func (r Residue) IsZero() bool

type Event struct {
    SchemaVersion   int        `json:"schema_version"`
    Sequence        uint64     `json:"sequence"`
    TimestampUTC    time.Time  `json:"timestamp_utc"`
    Generation      uint64     `json:"generation"`
    Level           string     `json:"level"`
    Component       string     `json:"component"`
    Stage           string     `json:"stage"`
    Event           string     `json:"event"`
    ElapsedMS       *int64     `json:"elapsed_ms,omitempty"`
    Message         string     `json:"message"`
    Detail          string     `json:"detail,omitempty"`
    DetailTruncated bool       `json:"detail_truncated,omitempty"`
    Residue         *Residue   `json:"residue,omitempty"`
}

type Batch struct {
    Events         []Event `json:"events"`
    NextSequence   uint64  `json:"next_sequence"`
    HasMore        bool    `json:"has_more"`
    OldestSequence uint64  `json:"oldest_sequence"`
}

type Sink interface { Record(Event) }
type Source interface { Batch(after uint64, limit int) Batch }

type RecorderConfig struct {
    Directory      string
    MemoryCapacity int
    MaxFileBytes   int64
    RetainFiles    int
    Now            func() time.Time
}

func NewRecorder(RecorderConfig) (*Recorder, error)
func (r *Recorder) Record(Event)
func (r *Recorder) Batch(after uint64, limit int) Batch
func (r *Recorder) Close() error
func SanitizeDetail(string, ...[]byte) (detail string, truncated bool)
func Validate(Event) error
func WithGeneration(context.Context, uint64) context.Context
func GenerationFromContext(context.Context) uint64
```

- Fixed levels: `info`, `warning`, `error`.
- Fixed event values: `started`, `succeeded`, `failed`, `state`.
- Fixed components: `controller`, `network`, `powershell`, `core`, `recovery`, `service`, `logging`.
- Fixed stages are exactly those approved in the design plus `logging_degraded`.

- [ ] **Step 1: Write failing schema and validation tests.** Cover every allowed enum, unknown values, negative elapsed time, missing required fields, a residue only on terminal/state events, and exact JSON field names. Add a table test that checks each timed stage can be represented as one `started` plus exactly one `succeeded` or `failed` event.
- [ ] **Step 2: Run the focused tests and observe RED.**

```powershell
& 'C:\Users\Eleme\codex_workspace\.tools\go1.27.0\go\bin\go.exe' test ./internal/traceevent -run 'Test(Event|Validate|StagePair)' -count=1
```

Expected: compile failure because `internal/traceevent` does not exist.

- [ ] **Step 3: Implement the immutable event model and strict validation.** Copy events and residue values at the recorder boundary; callers must not be able to mutate stored events. Assign `schema_version`, UTC timestamp, and strictly increasing sequence inside `Recorder.Record`, ignoring caller-supplied values for those three fields. Add private context-key helpers so an operation generation can be passed to lower layers without a package cycle.
- [ ] **Step 4: Write failing centralized redaction tests.** Include recognizable secrets in plain text, URI userinfo, `Proxy-Authorization`, JSON password/PIN fields, DPAPI-like/Base64 blobs, `agent.yaml`, `sing-box.json`, control characters, and a detail larger than 4096 bytes. Assert forbidden sentinel strings never appear and truncation is explicit.
- [ ] **Step 5: Implement `SanitizeDetail`.** Normalize whitespace, strip control characters, replace explicit redaction byte sequences, redact credential-shaped values, cap UTF-8 output at 4096 bytes without breaking a rune, and set `detail_truncated`.
- [ ] **Step 6: Write failing recorder tests.** Cover sequence ordering under concurrent writers, bounded ring overwrite, `after_sequence`, `limit`, `oldest_sequence`, `has_more`, deep-copy behavior, generation-specific fixed filenames, create-new semantics, terminal flush, the 2 MiB cap, a single truncation event, retention of only five matching JSONL files, ignoring unrelated directory entries, and disk-write degradation without blocking memory recording.
- [ ] **Step 7: Implement `Recorder`.** Create only the configured leaf directory under its already-owned parent, reject a non-directory target, use one mutex for sequence/ring/file state, open a new `trace-<UTC>-g<generation>.jsonl` file when generation changes, use `O_CREATE|O_EXCL`, flush terminal events, stop disk appends after the cap, and emit at most one in-memory `logging/logging_degraded/failed` event per affected generation.
- [ ] **Step 8: Run focused tests and race detection.**

```powershell
& 'C:\Users\Eleme\codex_workspace\.tools\go1.27.0\go\bin\go.exe' test ./internal/traceevent -count=1
& 'C:\Users\Eleme\codex_workspace\.tools\go1.27.0\go\bin\go.exe' test -race ./internal/traceevent -count=1
```

Expected: PASS with no race reports.

- [ ] **Step 9: Commit Task 1.**

```powershell
git add internal/traceevent
git commit -m "feat(trace): add bounded redacted event recorder"
```

---

### Task 2: Expose paginated traces through the existing Named Pipe and client API

**Files:**

- Modify: `internal/agent/pipe_windows.go`
- Modify: `internal/agent/pipe_stub.go`
- Modify: `internal/agent/pipe_windows_test.go`
- Modify: `internal/clientapi/client.go`
- Modify: `internal/clientapi/client_test.go`

**Protocol additions:**

```go
const ActionTrace = "trace"

type Request struct {
    ID            string `json:"id"`
    Action        string `json:"action"`
    AfterSequence uint64 `json:"after_sequence,omitempty"`
    Limit         int    `json:"limit,omitempty"`
}

func WithTraceSource(source traceevent.Source) PipeOption
func (c *Client) Trace(context.Context, uint64, int) (traceevent.Batch, error)
```

- `trace` is read-only and uses the current status state in the outer Response; `Response.Message` contains strict `TraceBatch` JSON.
- Default limit is 32, maximum request limit is 64, and the server shrinks a batch at event boundaries until the complete outer response is at most `MaxPipeFrameBytes`.

- [ ] **Step 1: Add failing pipe protocol tests.** Assert valid first-page/incremental/empty trace reads; monotonic cursor; `after_sequence` and `limit` rejection on non-trace actions; negative/over-limit values rejected; missing trace source rejected safely; response ID binding; unknown JSON fields rejected; and a worst-case detail batch is reduced below 64 KiB without cutting an event.
- [ ] **Step 2: Run the pipe tests and observe RED.**

```powershell
& 'C:\Users\Eleme\codex_workspace\.tools\go1.27.0\go\bin\go.exe' test ./internal/agent -run 'TestPipe.*Trace|TestPipe.*Request' -count=1
```

- [ ] **Step 3: Implement the pipe additions.** Keep the existing DACL and one-request-per-connection behavior. Decode strictly, validate action-specific fields, query the injected source, marshal the nested batch, and reduce by whole event until the complete response fits.
- [ ] **Step 4: Add failing client API tests.** Cover the exact trace request fields, deadlines, response-ID/state/error allowlists, strict nested batch decoding, unknown event fields, invalid enum/stage/schema rejection, non-monotonic sequences, and oversized frames.
- [ ] **Step 5: Implement `Client.Trace`.** Reuse the existing dial/deadline/request-ID path; do not add a second pipe or widen pipe permissions. Validate every returned event with `traceevent.Validate` before returning it.
- [ ] **Step 6: Run package regressions.**

```powershell
& 'C:\Users\Eleme\codex_workspace\.tools\go1.27.0\go\bin\go.exe' test ./internal/agent ./internal/clientapi -count=1
```

- [ ] **Step 7: Commit Task 2.**

```powershell
git add internal/agent/pipe_windows.go internal/agent/pipe_stub.go internal/agent/pipe_windows_test.go internal/clientapi
git commit -m "feat(pipe): stream sanitized trace batches"
```

---

### Task 3: Instrument Controller lifecycle and derive diagnostics from failed events

**Files:**

- Modify: `internal/agent/controller.go`
- Modify: `internal/agent/controller_test.go`

**Interface change:**

```go
type Dependencies struct {
    // existing fields remain
    Trace traceevent.Sink
}
```

Add private helpers that take an explicit generation, component, stage, start time, terminal result, detail, and optional residue. Never read `c.generation` without the controller mutex merely to log an event.

- [ ] **Step 1: Add failing Controller trace tests.** Use a recording sink and assert exact ordered stage pairs for successful schema-2 Connect, failure at every dependency/network/process boundary, Disconnect, Recover, cancellation, and readiness loss. Assert all events in one operation use its captured generation and parallel callers do not cross-contaminate generations.
- [ ] **Step 2: Add regression tests for the current blind spot.** Make `InstallPublicTCPBlock` return a staged error with empty detail and assert diagnostics still contain `stage=firewall_publish` and a synthesized non-secret detail. Assert `recordDiagnostic` uses the last failed TraceEvent and no longer discards an empty low-level stderr.
- [ ] **Step 3: Run focused tests and observe RED.**

```powershell
& 'C:\Users\Eleme\codex_workspace\.tools\go1.27.0\go\bin\go.exe' test ./internal/agent -run 'TestController.*Trace|TestController.*Diagnostic|TestController.*Generation' -count=1
```

- [ ] **Step 4: Instrument Controller.** Emit `request_received`, policy/binary/credential/config/core/TUN/route/connected stages. Each started event gets exactly one terminal event. Keep error-code mapping and fail-closed state behavior unchanged. Emit core-stop, restore, and recovery stages during Disconnect/Recover. Wrap every network call context with `traceevent.WithGeneration(ctx, generation)` so downstream events bind to the same captured operation.
- [ ] **Step 5: Make diagnostics a compatibility projection.** Store the most recent failed event's stage and sanitized detail; if detail is empty, synthesize a fixed description containing stage, cancellation/deadline classification, or error type but never raw credential/config data.
- [ ] **Step 6: Add lifecycle residue hooks without weakening `NetworkManager`.** Introduce an optional private capability interface used only for observability:

```go
type residueReporter interface {
    Residue(context.Context) (traceevent.Residue, error)
}
```

After restore/reconcile, emit `residue_verify` and only mark the operation disconnected when residue is zero. A nonzero residue maps to `restore_failed`; implementations without the optional interface retain current behavior and tests.

- [ ] **Step 7: Run Controller and full agent tests.**

```powershell
& 'C:\Users\Eleme\codex_workspace\.tools\go1.27.0\go\bin\go.exe' test ./internal/agent -count=1
```

- [ ] **Step 8: Commit Task 3.**

```powershell
git add internal/agent/controller.go internal/agent/controller_test.go
git commit -m "feat(agent): trace connection and recovery lifecycle"
```

---

### Task 4: Instrument Windows network and PowerShell operations with complete failure details

**Files:**

- Modify: `internal/agent/network_windows.go`
- Modify: `internal/agent/network_windows_test.go`
- Modify: `internal/agent/network_windows_integration_test.go`

**Interface additions:**

```go
type WindowsNetworkOption func(*WindowsNetworkManager)
func WithWindowsTraceSink(traceevent.Sink) WindowsNetworkOption
func NewWindowsNetworkManager(accessmodel.Policy, string, ...WindowsNetworkOption) (*WindowsNetworkManager, error)
func (m *WindowsNetworkManager) Residue(context.Context) (traceevent.Residue, error)
```

- Preserve all existing two-argument constructor call sites through the variadic option.
- Map current fixed PowerShell operations to approved stages: capture → `network_capture`; adapter identity/join → `adapter_scan`; rule publication → `firewall_publish`; ActiveStore readback → `active_store_verify`; emergency rules → `emergency_protection`; restore/reconcile → `network_restore` and `residue_verify`.

- [ ] **Step 1: Add failing PowerShell diagnostic tests.** Cover clean ErrorRecord/CLIXML, ordinary stderr, empty stderr with nonzero exit, context deadline, context cancellation, process start failure, transport/JSON decode failure, and output containing forbidden sentinel secrets. Every returned `fixedNetworkOperationError` must have nonempty approved stage and sanitized detail.
- [ ] **Step 2: Add failing trace tests for network operations.** Assert paired start/terminal events, elapsed milliseconds, adapter/rule/address counts rather than full address lists, ActiveStore expected/actual counts, emergency-protection outcome, and generation inherited from context.
- [ ] **Step 3: Run focused tests and observe RED.**

```powershell
& 'C:\Users\Eleme\codex_workspace\.tools\go1.27.0\go\bin\go.exe' test ./internal/agent -run 'TestWindowsNetwork.*(Diagnostic|Trace|Residue|PowerShell)' -count=1
```

- [ ] **Step 4: Consume context generation in network events.** Read `traceevent.GenerationFromContext(ctx)` for every emitted event. The network manager never guesses or stores a mutable current generation.
- [ ] **Step 5: Implement complete diagnostic synthesis in `run`.** Parse CLIXML first, then sanitized stderr, then context termination, then native exit/error type plus fixed operation name. Never serialize the input struct or raw PowerShell stdin into logs/errors.
- [ ] **Step 6: Implement network trace and residue count collection.** Reuse the existing fixed PowerShell transport and product ownership markers. `Residue` reports only managed-rule count, product-route count, product-TUN count, owned core-process count, snapshot presence, and ownership phase. It must not mutate state.
- [ ] **Step 7: Extend the LocalSystem integration test contract.** When explicit environment gates are absent it remains skipped. When enabled, require a complete capture/scan/publish/readback/restore/residue event timeline and zero residue after restore.
- [ ] **Step 8: Run all network tests.**

```powershell
& 'C:\Users\Eleme\codex_workspace\.tools\go1.27.0\go\bin\go.exe' test ./internal/agent -count=1
```

- [ ] **Step 9: Commit Task 4.**

```powershell
git add internal/agent/network_windows.go internal/agent/network_windows_test.go internal/agent/network_windows_integration_test.go internal/traceevent/event.go internal/traceevent/event_test.go
git commit -m "feat(windows): trace firewall and restore transactions"
```

---

### Task 5: Wire the recorder into the Windows service and preserve startup/stop recovery evidence

**Files:**

- Modify: `cmd/overseas-agent/main_windows.go`
- Modify: `cmd/overseas-agent/main_windows_test.go`

**Constants and ownership:**

```go
const traceDirectory = dataDirectory + `\logs`
```

`buildService` creates one recorder with production limits (bounded memory, 2 MiB, five files), injects it into Controller, WindowsNetworkManager, and PipeServer, and ensures it is flushed/closed after service shutdown. The service records generation 0 `service_recovery` events before SCM reports Running and records service-stop Disconnect before returning.

- [ ] **Step 1: Add failing service-construction tests.** Assert one shared recorder is injected into all three consumers, the exact fixed log directory is used, log initialization failure makes configuration invalid before SCM Running, and no user-controlled log path exists.
- [ ] **Step 2: Add failing service lifecycle tests.** Assert startup recovery emits start/terminal events; failed recovery prevents Running and returns `serviceExitRestore`; normal stop emits stop/disconnect/residue events and flushes before Execute returns; pipe failure still attempts traced Disconnect.
- [ ] **Step 3: Run tests and observe RED.**

```powershell
& 'C:\Users\Eleme\codex_workspace\.tools\go1.27.0\go\bin\go.exe' test ./cmd/overseas-agent -count=1
```

- [ ] **Step 4: Implement service wiring.** Add a closeable recorder field to `serviceHandler`; keep fatal startup errors generic on stderr; detailed sanitized reason is written only through the protected trace store where possible.
- [ ] **Step 5: Run service and agent regressions.**

```powershell
& 'C:\Users\Eleme\codex_workspace\.tools\go1.27.0\go\bin\go.exe' test ./cmd/overseas-agent ./internal/agent ./internal/traceevent -count=1
```

- [ ] **Step 6: Commit Task 5.**

```powershell
git add cmd/overseas-agent
git commit -m "feat(service): persist startup and shutdown traces"
```

---

### Task 6: Implement independent UI trace polling, timeline state, copying, restore, and safe retry

**Files:**

- Modify: `cmd/overseas-client/viewmodel.go`
- Modify: `cmd/overseas-client/viewmodel_test.go`
- Create: `cmd/overseas-client/traceview.go`
- Create: `cmd/overseas-client/traceview_test.go`

**ViewModel contract:**

```go
type serviceClient interface {
    // existing methods remain
    Trace(context.Context, uint64, int) (traceevent.Batch, error)
}

type ViewState struct {
    StatusText          string
    DetailText          string
    GenerationText      string
    StageText           string
    ProtectionText      string
    LogText             string
    PrimaryButtonText   string
    PrimaryEnabled      bool
    RestoreEnabled      bool
    CopyEnabled         bool
}

func (v *ViewModel) Restore(context.Context) error
func (v *ViewModel) CopyLogs() error
```

- Keep status polling at the existing interval and add a separate trace interval defaulting to 500 ms.
- Maintain an in-memory current-service-session event list bounded by the server ring capacity; the copy action selects all events in the current generation plus its separator/summary.

- [ ] **Step 1: Add failing formatter/timeline tests.** Assert local timestamp, `[INFO]/[WARN]/[ERROR]`, `→/✓/✕/!`, component/stage/event/elapsed text, indented detail, generation separators, ring-gap warning, residue summary, stable ordering/deduplication, and no forbidden secret sentinels.
- [ ] **Step 2: Implement pure timeline formatting.** Keep it platform-neutral and deterministic by injecting the local timezone in tests. Unknown enum/stage events never reach it because client validation rejects them.
- [ ] **Step 3: Add failing independent-poll tests.** Block fake `Connect` for longer than several trace intervals and prove trace batches update `LogText` while `busy=true`. Cover cursor advancement, temporary trace failure warning with bounded retry, gap detection via `oldest_sequence`, restart from cursor zero, and no duplicate events.
- [ ] **Step 4: Add failing safe-retry tests.** From failed state assert exact calls: `Disconnect` → `Diagnostics` → trace polling until matching-generation `residue_verify/succeeded` with `Residue.IsZero()` → `Connect`. Assert `restore_failed`, timeout, nonzero residue, missing residue proof, or context cancellation prevents Connect. Assert `Restore` only disconnects and never connects.
- [ ] **Step 5: Add failing copy tests.** `CopyLogs` uses already-sanitized local trace events for the current generation and does not make a diagnostics/pipe call. It includes visible status/protection summary and all current-generation detail lines.
- [ ] **Step 6: Run ViewModel tests and observe RED.**

```powershell
& 'C:\Users\Eleme\codex_workspace\.tools\go1.27.0\go\bin\go.exe' test ./cmd/overseas-client -run 'Test(ViewModel|TraceTimeline)' -count=1
```

- [ ] **Step 7: Implement the two polling loops and action state machine.** Status Refresh may still skip while busy; trace Refresh must never check busy. Use one close channel and wait groups so `Close` terminates both loops. Do not hold the ViewModel mutex during a pipe call, clipboard call, or user callback.
- [ ] **Step 8: Implement safe retry and explicit restore.** Failed-state primary action is `安全重试`; connected-state primary action remains Disconnect; disconnected-state primary action is Connect. If zero-residue proof is absent, render the blocking reason and keep primary Connect disabled until a successful Restore path produces proof.
- [ ] **Step 9: Run ViewModel tests with race detection.**

```powershell
& 'C:\Users\Eleme\codex_workspace\.tools\go1.27.0\go\bin\go.exe' test ./cmd/overseas-client -count=1
& 'C:\Users\Eleme\codex_workspace\.tools\go1.27.0\go\bin\go.exe' test -race ./cmd/overseas-client -count=1
```

- [ ] **Step 10: Commit Task 6.**

```powershell
git add cmd/overseas-client/viewmodel.go cmd/overseas-client/viewmodel_test.go cmd/overseas-client/traceview.go cmd/overseas-client/traceview_test.go
git commit -m "feat(client): add live trace and safe retry state"
```

---

### Task 7: Build the default-expanded 820×620 Windows debug console

**Files:**

- Modify: `cmd/overseas-client/main_windows.go`
- Create: `cmd/overseas-client/logscroll_windows.go`
- Create: `cmd/overseas-client/logscroll_windows_test.go`
- Modify: `cmd/overseas-client/manifest_test.go`

**UI layout:**

- Fixed initial/minimum size approximately 820×620, vertically resizable upward.
- Top: title, status, generation, current stage, and fail-closed/residue summary.
- Middle: default-expanded multiline read-only `walk.TextEdit` using a Windows monospaced font.
- Bottom: primary action, `仅恢复网络`, and `复制全部日志`.

- [ ] **Step 1: Add failing source/UI contract tests.** Assert dimensions, read-only multiline log control, three buttons and bindings, default-visible log area, close handling, and `window.Synchronize` around ViewModel callbacks.
- [ ] **Step 2: Add failing pure scroll-state tests.** Create a small `logScrollState` that receives `atBottom` and text-change signals. Assert new logs follow only when at bottom; user scroll-up pauses; returning to bottom resumes; replacing text never steals selection while paused.
- [ ] **Step 3: Run focused tests and observe RED.**

```powershell
& 'C:\Users\Eleme\codex_workspace\.tools\go1.27.0\go\bin\go.exe' test ./cmd/overseas-client -run 'Test(BuildWindow|LogScroll|Manifest)' -count=1
```

- [ ] **Step 4: Implement the window.** Use `TextEdit.SetReadOnly(true)`, `SetTextSelection`, and `ScrollToCaret`. Detect bottom position with a narrow Windows helper around the control's vertical scroll information; do not globally hook input or add a background helper process.
- [ ] **Step 5: Bind all ViewState fields and actions.** Primary calls `Toggle`, restore calls `Restore`, copy calls `CopyLogs`; failures show a bounded generic message while the timeline retains technical detail. Disable buttons according to the ViewModel state.
- [ ] **Step 6: Build the Windows client and run its tests.**

```powershell
& 'C:\Users\Eleme\codex_workspace\.tools\go1.27.0\go\bin\go.exe' test ./cmd/overseas-client -count=1
$env:GOOS='windows'; $env:GOARCH='amd64'; & 'C:\Users\Eleme\codex_workspace\.tools\go1.27.0\go\bin\go.exe' build -trimpath -o build\v16-check\overseas-client.exe ./cmd/overseas-client; Remove-Item Env:GOOS,Env:GOARCH
```

- [ ] **Step 7: Commit Task 7.**

```powershell
git add cmd/overseas-client
git commit -m "feat(ui): show default-expanded debug timeline"
```

---

### Task 8: Extend verification contracts for logs, protocol, LocalSystem, and installer lifecycle

**Files:**

- Modify: `scripts/windows/verify-client-network-transaction.ps1`
- Modify: `tests/powershell/ClientNetworkTransaction.Tests.ps1`
- Modify: `tests/powershell/ClientInstall.Tests.ps1`
- Modify: `tests/powershell/Runbook.Tests.ps1`
- Modify: `docs/poc-runbook.md`

- [ ] **Step 1: Add failing Pester contracts.** Require the trace action/schema, protected `ProgramData\...\logs` directory, exact 2 MiB/five-file constants, default-expanded debug UI, no secret-bearing trace fields, and restore-first safe-retry ordering.
- [ ] **Step 2: Add failing LocalSystem transaction assertions.** The verification script must capture trace batches before/after publish and restore; require paired `network_capture`, `adapter_scan`, `firewall_publish`, `active_store_verify`, `network_restore`, and `residue_verify` events; require a terminal zero residue after explicit restore.
- [ ] **Step 3: Run focused Pester and observe RED.**

```powershell
Invoke-Pester -Path tests\powershell\ClientNetworkTransaction.Tests.ps1,tests\powershell\ClientInstall.Tests.ps1,tests\powershell\Runbook.Tests.ps1 -Output Detailed
pwsh -NoProfile -Command "Invoke-Pester -Path 'tests/powershell/ClientNetworkTransaction.Tests.ps1','tests/powershell/ClientInstall.Tests.ps1','tests/powershell/Runbook.Tests.ps1' -Output Detailed"
```

- [ ] **Step 4: Implement scripts and runbook changes.** Keep the live transaction behind its existing explicit gates. The runbook must state that generation 5 evidence is captured before recovery, that only service Disconnect/Recover performs cleanup, and that the user closes FlClash only for final acceptance.
- [ ] **Step 5: Run the focused suites under both PowerShell engines.** Expect zero failures and no live network mutation from the unit/contract suite.
- [ ] **Step 6: Commit Task 8.**

```powershell
git add scripts/windows/verify-client-network-transaction.ps1 tests/powershell/ClientNetworkTransaction.Tests.ps1 tests/powershell/ClientInstall.Tests.ps1 tests/powershell/Runbook.Tests.ps1 docs
git commit -m "test(windows): gate observable recovery lifecycle"
```

---

### Task 9: Verify, publish, recover generation 5, install v16, and hand off the live test

**Files:**

- Generated only: `build/v16-*`
- Generated only: signed v16 MSI and release evidence
- No source edit is permitted after the release commit without restarting verification and publishing a new package.

- [ ] **Step 1: Run the complete non-mutating verification matrix.**

```powershell
& 'C:\Users\Eleme\codex_workspace\.tools\go1.27.0\go\bin\go.exe' test ./... -count=1
& 'C:\Users\Eleme\codex_workspace\.tools\go1.27.0\go\bin\go.exe' vet ./...
Invoke-Pester -Path tests\powershell -Output Detailed
pwsh -NoProfile -Command "Invoke-Pester -Path 'tests/powershell' -Output Detailed"
Get-ChildItem scripts,deploy,tests -Recurse -Filter *.ps1 | ForEach-Object { $tokens=$null; $errors=$null; [void][System.Management.Automation.Language.Parser]::ParseFile($_.FullName,[ref]$tokens,[ref]$errors); if ($errors) { throw ($errors | Out-String) } }
```

Expected: every Go/Pester/AST check passes; no live network state changes.

- [ ] **Step 2: Confirm the release commit and clean tree.** Run `git status --short`, require no output, and record `git rev-parse HEAD`. The signed artifact manifest must bind this exact commit.
- [ ] **Step 3: Capture the untouched generation 5 baseline.** Record current diagnostics JSON, service/PID, exact managed-rule count, snapshot existence/phase, product-route count, product-TUN count, sing-box process count, runtime-owned/config existence, and timestamp into a generated v16 evidence directory. Do not record rule address collections or credentials.
- [ ] **Step 4: Perform the only approved cleanup path.** Invoke the running service's existing Disconnect action (or service Recover if the pipe cannot answer). Require `state=disconnected`; then independently prove zero managed rules, zero product routes, zero product TUNs, zero sing-box processes, and no owned network-state snapshot. If cleanup fails, stop: keep v15 installed, preserve evidence, and do not install v16.
- [ ] **Step 5: Run the LocalSystem transaction gate against the release binaries.** Use the existing gated verifier. Require complete trace stage pairs and terminal zero residue. If this mutating gate fails, invoke explicit recovery, capture its trace/evidence, and stop release installation.
- [ ] **Step 6: Publish signed v16 artifacts.** Use `scripts/windows/publish-client-release.ps1`, the locked Go toolchain, SignTool at `C:\Program Files (x86)\Windows Kits\10\bin\10.0.26100.0\x64\signtool.exe`, and certificate thumbprint `6A9D8BC41086C6B764B8C7439E797671EF83C15E`. Verify every first-party executable and MSI signature, the signed manifest, source commit, payload hashes, and schema-2 HTTP CONNECT policy.
- [ ] **Step 7: Inspect the MSI before execution.** Decompile/extract it and require the exact payload allowlist, valid signer, manual service semantics, no credential provisioner, no proxy/FlClash mutation, and a single product registration after upgrade. Record the new MSI SHA-256 and ProductCode; never reuse the v15 ProductCode `{1FD6223B-0925-4522-B5CE-6BA9CBFC3CEC}`.
- [ ] **Step 8: Upgrade v15 to v16 with verbose logs.** Stop the service only after zero-residue proof, uninstall the sole v15 product normally, prove zero registrations/residue, install the signed v16 MSI, and retain verbose uninstall/install logs. If any postcondition fails, use the normal installer rollback/uninstall path and preserve evidence.
- [ ] **Step 9: Verify installed idle state.** Require exactly one v16 registration, installed hashes equal the signed manifest, required signatures valid, service Running, pipe status reachable, trace action readable, log-directory ACL limited to SYSTEM/Administrators, one startup recovery trace, and zero network residue before user action.
- [ ] **Step 10: Open the v16 UI without connecting.** Confirm approximately 820×620 layout, default-expanded log timeline, generation/stage/protection summary, and three buttons. Do not close FlClash or start the real connection on the user's behalf.
- [ ] **Step 11: Hand off the reliable live test.** Ask the user to fully exit FlClash, click once, and test overseas plus internal sites. On failure they click `复制全部日志`; on success they close/restore and report both browsing and UI result. Do not claim end-to-end success until the user reports it and post-disconnect zero residue is independently verified.
- [ ] **Step 12: Commit only documentation/evidence indexes if tracked policy requires them.** Generated secrets, MSI, logs, and machine-specific evidence remain outside Git. Run the complete verification matrix again for any tracked edit.

---

## Completion Criteria

- Every timed stage has one start and one terminal event in the same generation.
- The UI continues to receive trace events while Connect is blocked.
- Every failure, including empty PowerShell stderr, has a stage and sanitized technical detail.
- Failure remains fail-closed and displays a residue summary.
- Safe Retry cannot call Connect until explicit Disconnect succeeds and a matching-generation zero-residue event is observed.
- Recent trace evidence survives UI/service failure within the five-file/2 MiB bounds.
- The signed v16 MSI is bound to a clean verified commit and installs as the sole product.
- A user-run live result, successful or failed, is sufficiently detailed to locate the exact stage; end-to-end acceptance additionally requires successful browsing and zero residue after disconnect.
