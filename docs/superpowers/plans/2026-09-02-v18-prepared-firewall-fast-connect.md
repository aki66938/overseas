# v18 Prepared Firewall Fast Connect Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the v17 connection-time PowerShell rebuild loop with a persistent Disabled firewall rule pool, native Windows network snapshots, transactional automatic restore, accurate diagnostics, and a stable prepared-state connection time of at most 15 seconds.

**Architecture:** The LocalSystem service owns two separately sealed records under ProgramData: a reusable prepared baseline/rule ledger and a short-lived active connection snapshot. Windows IP Helper APIs provide deterministic adapter, DNS, metric, and route data; PowerShell is restricted to named firewall mutations and infrequent deep audits. The controller treats connection as a six-step transaction, starts monitoring only after `connected`, and completes automatic reverse-order restoration before reporting any safe failure.

**Tech Stack:** Go 1.27.0, `golang.org/x/sys/windows` v0.46.0, Windows IP Helper API, Windows NetSecurity PowerShell cmdlets, sing-box 1.13.19, `go-winio`, `lxn/walk`, PowerShell 5.1/7, Pester, WiX v4, Windows SDK SignTool.

## Global Constraints

- Work only in `C:\Users\Eleme\codex_workspace\overseas-access-gateway\.worktrees\windows-forwarding-poc` on `feature/windows-forwarding-poc`.
- Use `C:\Users\Eleme\codex_workspace\.tools\go1.27.0\go\bin\go.exe` for every Go command.
- Preserve fail-closed ordering: no core start before normal rules are Enabled and verified; no route/DNS activation before the exact new TUN identity is owned.
- Normal connection failures must automatically restore ordinary networking before the pipe response returns. Only an unprovable restore may leave Emergency Enabled and enter `failed_safe`.
- A valid Disabled prepared rule is reusable state, not active residue. Enabled product rules, active snapshots, product routes, product TUNs, and product core processes must all be zero while safely disconnected.
- Do not start a 250 ms firewall reconciliation loop. Runtime fingerprint checks are 30 seconds; deep firewall audits are 5 minutes; neither starts before `connected`.
- Do not modify VM101, the telecom client, `172.20.9.15:8080`, FlClash, system proxy settings, unrelated firewall rules, or non-product routes.
- Unit and ordinary integration tests must not mutate the live firewall. Live LocalSystem/firewall gates require their existing explicit environment guard and occur only in Task 10.
- The user performs real Connect/Disconnect clicks and overseas-site checks. Development, build, signing, installation, read-only inspection, and approved product-owned recovery are performed by the implementation worker.
- Never log credentials, Proxy-Authorization, DPAPI material, complete sing-box configuration, complete prefix sets, or full PowerShell envelopes.
- Each behavior slice follows RED → minimal GREEN → focused regression → commit. Generated `build/`, `dist/`, MSI, extraction, and evidence files remain untracked.

---

### Task 1: Establish the prepared-state, status, error, and trace contracts

**Files:**

- Modify: `internal/accessmodel/model.go`
- Modify: `internal/accessmodel/validate_test.go`
- Modify: `internal/agent/controller.go`
- Modify: `internal/agent/controller_test.go`
- Modify: `internal/traceevent/event.go`
- Modify: `internal/traceevent/event_test.go`
- Create: `internal/agent/prepared.go`
- Create: `internal/agent/prepared_test.go`

**Interfaces and durable model:**

```go
const (
    StatePreparing  ConnectionState = "preparing"
    StatePrepared   ConnectionState = "prepared"
    StateConnecting ConnectionState = "connecting"
    StateConnected  ConnectionState = "connected"
    StateRestoring  ConnectionState = "restoring"
    StateFailedSafe ConnectionState = "failed_safe"
)

type PreparedNetwork struct {
    Generation   uint64 `json:"generation"`
    Fingerprint  string `json:"fingerprint"`
    AdapterCount int    `json:"adapter_count"`
    RuleCount    int    `json:"rule_count"`
}

type WindowsPreparedState struct {
    Version               int                    `json:"Version"`
    Generation            uint64                 `json:"Generation"`
    PolicySHA256          string                 `json:"PolicySHA256"`
    RuleDefinitionVersion int                    `json:"RuleDefinitionVersion"`
    FingerprintSHA256     string                 `json:"FingerprintSHA256"`
    Baseline              WindowsNetworkBaseline `json:"Baseline"`
    Rules                 []WindowsPreparedRule  `json:"Rules"`
    IntegritySHA256       string                 `json:"IntegritySHA256"`
}
```

Add the exact error codes `prepared_state_unavailable`, `network_changed`, `firewall_enable_failed`, `firewall_verify_failed`, `tun_not_found`, `tun_identity_mismatch`, and `automatic_restore_failed`. Retain `core_start_failed`, `core_not_ready`, and `route_activation_failed`; remove controller paths that collapse firewall or timeout errors into a TUN error.

Add trace stages `network_prepare`, `network_fingerprint`, `firewall_prepare`, `firewall_enable`, `firewall_verify`, `monitor_start`, and `automatic_restore`. Extend `traceevent.Residue` with `DisabledPreparedRules int`; `IsZero()` intentionally ignores that field but still requires zero active residue.

- [ ] **Step 1: Write failing enum, JSON, sealing, and residue tests.** Assert exactly the six approved steady/transition states, exact JSON field names, monotonic non-zero prepared generations, lowercase 64-character SHA-256 fields, canonical ordering, tamper rejection, and `Residue{DisabledPreparedRules: 9}.IsZero() == true`.
- [ ] **Step 2: Run focused tests and observe RED.**

```powershell
$go = 'C:\Users\Eleme\codex_workspace\.tools\go1.27.0\go\bin\go.exe'
& $go test ./internal/accessmodel ./internal/traceevent ./internal/agent -run 'Test(ConnectionState|Prepared|Residue|ErrorCode|TraceStage)' -count=1
```

Expected: compile/assertion failures for absent states, types, codes, stages, and Disabled prepared-rule residue.

- [ ] **Step 3: Implement the model and strict validation.** Use canonical sorted copies before sealing. Reject generation zero, duplicate rule names, invalid adapter identities, unknown versions, malformed hashes, and inconsistent rule counts. Do not add migration fallback that silently trusts unsealed data.
- [ ] **Step 4: Re-run focused tests to GREEN and commit.**

```powershell
& $go test ./internal/accessmodel ./internal/traceevent ./internal/agent -run 'Test(ConnectionState|Prepared|Residue|ErrorCode|TraceStage)' -count=1
git add internal/accessmodel internal/traceevent internal/agent/controller.go internal/agent/controller_test.go internal/agent/prepared.go internal/agent/prepared_test.go
git commit -m "feat(windows): define prepared connection state contracts"
```

---

### Task 2: Read the Windows network baseline through IP Helper APIs

**Files:**

- Create: `internal/agent/network_native.go`
- Create: `internal/agent/network_native_test.go`
- Create: `internal/agent/network_native_windows.go`
- Create: `internal/agent/network_native_windows_test.go`
- Modify: `internal/agent/network_windows.go`
- Modify: `internal/agent/network_windows_test.go`

**Normalized boundary:**

```go
type WindowsNetworkBaseline struct {
    Adapters   []WindowsNativeAdapter   `json:"Adapters"`
    Interfaces []WindowsNativeInterface `json:"Interfaces"`
    Routes     []WindowsNativeRoute     `json:"Routes"`
    NodeRoutes []WindowsNodeRouteSnapshot `json:"NodeRoutes"`
}

type nativeNetworkReader interface {
    Baseline(context.Context, []string) (WindowsNetworkBaseline, error)
    Fingerprint(context.Context, []string) (string, error)
}

type ipHelperAPI interface {
    Adapters(context.Context) ([]ipHelperAdapter, error)
    IPv4Interfaces(context.Context) ([]ipHelperInterface, error)
    IPv4Routes(context.Context) ([]ipHelperRoute, error)
}
```

`windowsIPHelperAPI` must call `windows.GetAdaptersAddresses` with `GAA_FLAG_INCLUDE_GATEWAYS`, bind each returned adapter LUID through `windows.GetIpInterfaceEntry`, and call `windows.GetIpForwardTable2(windows.AF_INET, ...)`; it must call `windows.FreeMibTable` on every successful allocated route table. The LUID-bound entry call is required because the live host proved that treating the variable-length `MIB_IPINTERFACE_TABLE` as a Go slice produced conflicting duplicate indices. Convert linked-list socket addresses immediately into owned Go values.

- [ ] **Step 1: Write failing pure normalization tests.** Cover shuffled API rows, duplicate DNS addresses, down/tunnel/loopback adapters, automatic/manual metrics, default routes, on-link next hops, multiple equal-cost routes, node `/32` bypass selection, stable sorting, and fingerprint change on every restore-relevant field.
- [ ] **Step 2: Run the pure tests and observe RED.**

```powershell
& $go test ./internal/agent -run 'TestNative(NetworkBaseline|Fingerprint|NodeRoute)' -count=1
```

- [ ] **Step 3: Implement the platform-independent normalizer and fingerprint.** Hash canonical JSON containing adapter GUID/index/alias/status/DNS, IPv4 metric/automatic flag, default routes, and chosen node routes. Exclude transient counters, timestamps, and link speeds.
- [ ] **Step 4: Write failing Windows binding tests.** Inject a fake `ipHelperAPI` to prove every allocated table is released, buffer-resize handling for `GetAdaptersAddresses` is bounded, malformed sockaddr/UTF-16 data fails closed, context cancellation is observed between API calls, and no PowerShell runner is invoked.
- [ ] **Step 5: Implement the Windows bindings and compatibility comparison helper.** Keep the old capture script available only to a test helper in this task. Compare normalized native output with normalized legacy PowerShell output for fixture inputs; do not retain the legacy script on the production connect path.
- [ ] **Step 6: Run unit tests, Windows compile, and commit.**

```powershell
& $go test ./internal/agent -run 'TestNative|TestWindowsIPHelper' -count=1
& $go test ./internal/agent -count=1
& $go test ./cmd/overseas-agent -count=1
git add internal/agent/network_native.go internal/agent/network_native_test.go internal/agent/network_native_windows.go internal/agent/network_native_windows_test.go internal/agent/network_windows.go internal/agent/network_windows_test.go
git commit -m "feat(windows): capture network baseline with IP Helper"
```

---

### Task 3: Cache successful core verification against immutable file evidence

**Files:**

- Modify: `internal/coreverify/verify.go`
- Modify: `internal/coreverify/verify_test.go`
- Create: `internal/coreverify/cache.go`
- Create: `internal/coreverify/cache_test.go`
- Create: `internal/coreverify/fileid_windows.go`
- Create: `internal/coreverify/fileid_windows_test.go`
- Modify: `cmd/overseas-agent/main_windows.go`
- Modify: `cmd/overseas-agent/main_windows_test.go`

**Interfaces:**

```go
type FileIdentity struct {
    VolumeSerialNumber uint32
    FileIndex          uint64
    Size               int64
    LastWriteTime      int64
}

type Evidence struct {
    Identity               FileIdentity
    SHA256                 string
    AuthenticodeStatus     string
    AuthenticodeThumbprint string
}

type CachedVerifier struct { /* mutex + one successful evidence entry */ }

func NewCachedVerifier(expectedSHA256 string, signerAllowlist []string) (*CachedVerifier, error)
func (v *CachedVerifier) Verify(path string) error
```

- [ ] **Step 1: Write failing cache tests.** Count full hash/signature inspections. Require the second unchanged verification to use only file identity, and require a full recheck after path identity, volume/file index, length, write time, expected hash, signer allowlist, Authenticode status, or thumbprint changes. Failures are never cached.
- [ ] **Step 2: Run focused tests and observe RED.**

```powershell
& $go test ./internal/coreverify ./cmd/overseas-agent -run 'Test(CachedVerifier|FileIdentity|BuildServiceUsesCachedVerifier)' -count=1
```

- [ ] **Step 3: Refactor full verification to return `Evidence` without weakening checks.** `GetFileInformationByHandle` supplies the Windows identity. Keep the existing exported `Verify` as a non-cached compatibility wrapper. Empty Authenticode thumbprint is valid only under the existing explicitly unsigned pinned-binary policy.
- [ ] **Step 4: Construct one `CachedVerifier` in `buildService` and pass the same `Verify` method to both Controller and supervisor.** This removes the current duplicate 2.8-second full verification while preserving the suspended-launch identity check.
- [ ] **Step 5: Run focused and regression tests, then commit.**

```powershell
& $go test ./internal/coreverify ./internal/supervisor ./cmd/overseas-agent -count=1
git add internal/coreverify cmd/overseas-agent/main_windows.go cmd/overseas-agent/main_windows_test.go
git commit -m "perf(core): cache verified binary identity evidence"
```

---

### Task 4: Build and own the Disabled prepared firewall rule pool

**Files:**

- Create: `internal/agent/firewall_pool.go`
- Create: `internal/agent/firewall_pool_test.go`
- Create: `internal/agent/firewall_pool_windows.go`
- Modify: `internal/agent/network_windows.go`
- Modify: `internal/agent/network_windows_test.go`
- Modify: `tests/powershell/ClientFirewallInterfaces.Tests.ps1`
- Modify: `tests/powershell/ClientNetworkTransaction.Tests.ps1`

**Rule and operation contracts:**

```go
const windowsFirewallRuleDefinitionVersion = 2

type WindowsPreparedRule struct {
    Name               string   `json:"Name"`
    InterfaceGuid      string   `json:"InterfaceGuid,omitempty"`
    InterfaceAlias     string   `json:"InterfaceAlias,omitempty"`
    Protocol           string   `json:"Protocol"`
    RemotePorts        []string `json:"RemotePorts,omitempty"`
    RemoteAddressesSHA string   `json:"RemoteAddressesSHA"`
    Emergency          bool     `json:"Emergency"`
    ExpectedEnabled    bool     `json:"ExpectedEnabled"`
}
```

Add operations `firewall_prepare`, `firewall_enable`, `firewall_verify`, `firewall_disable`, and `firewall_audit`. A normal adapter rule is exactly `RegenBioOverseasAccess.BlockPublicAny.<canonical-guid-without-braces>`, outbound/block/Any, exact interface alias, product group, and Disabled during preparation. DNS UDP/53 and TCP/53 rules cover the complete protected-interface alias set. Emergency is never part of normal batch enable.

- [ ] **Step 1: Write failing Go rule-plan and ownership tests.** For seven adapters require seven Any rules + two DNS rules + one Emergency rule, deterministic names/order, no legacy TCP/UDP/QUIC rules, definition hash binding, Disabled expected state, and exact ledger equality. Reject unknown group members, duplicate names, missing filters, altered aliases, changed remote-address hash, unexpected Enabled state, or an unsealed ledger.
- [ ] **Step 2: Write failing Pester script contracts.** Require full query materialization (`@(...)`) before exact-name disable/delete loops; `Get-NetFirewallAddressFilter`, `Get-NetFirewallPortFilter`, and `Get-NetFirewallInterfaceFilter` definition checks; exact ActiveStore readback; and absence of a lazy `Get-NetFirewallRule | Remove-NetFirewallRule` pipeline.
- [ ] **Step 3: Run RED tests.**

```powershell
& $go test ./internal/agent -run 'Test(PreparedFirewall|FirewallLedger|FirewallRulePlan)' -count=1
powershell.exe -NoProfile -Command "$r=Invoke-Pester -Script @('tests/powershell/ClientFirewallInterfaces.Tests.ps1','tests/powershell/ClientNetworkTransaction.Tests.ps1') -PassThru; if($r.FailedCount){exit 1}"
```

- [ ] **Step 4: Implement rule planning and scripts.** `firewall_prepare` may create/replace only rules proven owned by the sealed ledger; any unowned/changed collision first enables the already-defined Emergency rule and returns a staged error. `firewall_enable` and `firewall_disable` use exact materialized names. `firewall_verify` checks only enabled normal rules; `firewall_audit` checks complete definitions and unknown group members.
- [ ] **Step 5: Add runner tests for partial mutation.** Inject failure after each rule and prove Emergency is attempted, the original failure stage is retained, and automatic restoration can disable every exactly owned rule without deleting the pool.
- [ ] **Step 6: Run dual GREEN tests and commit.**

```powershell
& $go test ./internal/agent -run 'Test(PreparedFirewall|FirewallLedger|FirewallRulePlan|Firewall.*Partial)' -count=1
powershell.exe -NoProfile -Command "$r=Invoke-Pester -Script @('tests/powershell/ClientFirewallInterfaces.Tests.ps1','tests/powershell/ClientNetworkTransaction.Tests.ps1') -PassThru; if($r.FailedCount){exit 1}"
pwsh -NoProfile -Command "$r=Invoke-Pester -Path 'tests/powershell/ClientFirewallInterfaces.Tests.ps1','tests/powershell/ClientNetworkTransaction.Tests.ps1' -PassThru; if($r.FailedCount){exit 1}"
git add internal/agent/firewall_pool.go internal/agent/firewall_pool_test.go internal/agent/firewall_pool_windows.go internal/agent/network_windows.go internal/agent/network_windows_test.go tests/powershell/ClientFirewallInterfaces.Tests.ps1 tests/powershell/ClientNetworkTransaction.Tests.ps1
git commit -m "feat(windows): prepare owned disabled firewall pool"
```

---

### Task 5: Implement prepared generations and the fast network-manager path

**Files:**

- Modify: `internal/agent/controller.go`
- Modify: `internal/agent/network_windows.go`
- Modify: `internal/agent/network_windows_test.go`
- Modify: `internal/agent/prepared.go`
- Modify: `internal/agent/prepared_test.go`
- Modify: `cmd/overseas-agent/main_windows.go`

**Network manager interface:**

```go
type NetworkManager interface {
    Prepare(context.Context) (PreparedNetwork, error)
    Capture(context.Context, PreparedNetwork) (any, error)
    EnableProtection(context.Context, PreparedNetwork) error
    WaitTUNReady(context.Context) error
    ActivateTUNRoutes(context.Context) error
    StartMonitor(context.Context, PreparedNetwork) (<-chan error, error)
    Restore(context.Context, any) error
    Reconcile(context.Context) error
}
```

Use `C:\ProgramData\RegenBio\OverseasAccess\prepared-network.json` for the sealed prepared state and retain `network-state.json` only for an active transaction. `Prepare` reads a native baseline, computes the policy/rule/fingerprint tuple, reuses an exact valid Disabled pool, or builds a new generation and atomically publishes it. `Capture` rechecks the lightweight fingerprint and writes the active snapshot without PowerShell.

- [ ] **Step 1: Update fakes and write failing prepared-generation tests.** Cover first preparation, unchanged reuse without firewall writes, topology/policy/rule-version invalidation, concurrent callers coalescing to one build, canceled waiter isolation, active-transaction exclusion, atomic write failure, and stale generation refusal.
- [ ] **Step 2: Write the v17 regression tests before implementation.** A successful `WaitTUNReady` must return without `scan`, `block`, `verify`, or `protectionRunMu`; connection startup must not start any monitor; the operation sequence before core start is exactly fingerprint → active snapshot → enable → verify.
- [ ] **Step 3: Run RED tests.**

```powershell
& $go test ./internal/agent -run 'TestWindowsNetwork(Prepare|Generation|FastPath|WaitTUNReadyNoFirewallReconcile)' -count=1
```

- [ ] **Step 4: Implement prepared storage and lifecycle.** Derive prepared/ledger paths from the validated state directory, use the existing atomic owner-protected publisher, and increment generation only after a complete Disabled pool is verified. Remove `protectionInterval`, `protectionRunMu`, `monitorProtection`, and the post-TUN call to `reconcileProtection`.
- [ ] **Step 5: Implement fast enable/verify and native snapshot capture.** Enabling does not re-enumerate adapters or recreate rules. Verify count, Enabled, Action, direction, group, definition version, and prepared generation. Stage every failure at its source.
- [ ] **Step 6: Run focused tests with repetition/race and commit.**

```powershell
& $go test ./internal/agent -run 'TestWindowsNetwork(Prepare|Generation|FastPath|WaitTUNReadyNoFirewallReconcile)' -count=20
& $go test -race ./internal/agent -run 'TestWindowsNetwork(Prepare|Generation|FastPath)' -count=5
git add internal/agent cmd/overseas-agent/main_windows.go
git commit -m "perf(windows): add prepared generation fast path"
```

---

### Task 6: Make Connect/Disconnect one automatic restoration transaction

**Files:**

- Modify: `internal/agent/controller.go`
- Modify: `internal/agent/controller_test.go`
- Modify: `internal/agent/pipe_windows_test.go`
- Modify: `internal/agent/pipe_stub_test.go`
- Modify: `internal/clientapi/client.go`
- Modify: `internal/clientapi/client_test.go`

**Status extension:**

```go
type Status struct {
    State       accessmodel.ConnectionState `json:"state"`
    ErrorCode   string `json:"error_code,omitempty"`
    Message     string `json:"message,omitempty"`
    Phase       string `json:"phase,omitempty"`
    Step        int    `json:"step,omitempty"`
    TotalSteps  int    `json:"total_steps,omitempty"`
    ElapsedMS   int64  `json:"elapsed_ms,omitempty"`
}
```

`prepared` is the safe disconnected/connectable state. A connection-stage failure whose automatic restore succeeds returns `prepared` plus the original `ErrorCode`; `failed_safe` is reserved for `automatic_restore_failed` with Emergency retained. The six displayed connection steps are fingerprint/snapshot, firewall, core, TUN, route/DNS, connected.

- [ ] **Step 1: Write failing success-order tests.** Require Prepare/fingerprint/capture/enable before core start; TUN before routes; `StartMonitor` only after status becomes connected; and no hidden network call after TUN ownership except route activation.
- [ ] **Step 2: Write a failure-injection matrix.** Fail Prepare, Capture, Enable, firewall verify, config render, process creation, core ready, TUN absent, TUN identity mismatch, route activation, and cancellation. Assert exact error code/stage, reverse-order stop/restore, zero active residue, original error preserved when restore succeeds, and `automatic_restore_failed` only when restore proof fails.
- [ ] **Step 3: Add state and pipe compatibility tests.** Validate all six new states, phase fields, a `prepared` response carrying a last-attempt error, and retry without a preliminary Disconnect. Reject unknown state/phase/step combinations in `clientapi`.
- [ ] **Step 4: Run RED tests.**

```powershell
& $go test ./internal/agent ./internal/clientapi -run 'TestController(FastConnect|AutomaticRestore|FailureMatrix|StateMachine)|Test(Pipe|Client).*Prepared' -count=1
```

- [ ] **Step 5: Implement a single `restoreTransaction` helper.** It stops/waits monitor, stops and proves the Job Object process tree, restores DNS/metrics/routes, disables normal and Emergency rules, deletes only the active snapshot, and verifies active residue zero. Both explicit Disconnect and every failed Connect call this helper.
- [ ] **Step 6: Implement precise boundary errors.** `WaitTUNReady` returns `tun_not_found` only for its own deadline and `tun_identity_mismatch` for a present but invalid candidate. Preserve staged firewall, monitor, PowerShell, and outer-context errors; never recast them as TUN.
- [ ] **Step 7: Run focused tests with repetition/race and commit.**

```powershell
& $go test ./internal/agent ./internal/clientapi -run 'TestController(FastConnect|AutomaticRestore|FailureMatrix|StateMachine)|Test(Pipe|Client).*Prepared' -count=20
& $go test -race ./internal/agent ./internal/clientapi -count=1
git add internal/agent internal/clientapi
git commit -m "fix(agent): restore every failed connection transaction"
```

---

### Task 7: Add post-connect fingerprint monitoring and infrequent deep audit

**Files:**

- Create: `internal/agent/network_monitor.go`
- Create: `internal/agent/network_monitor_test.go`
- Modify: `internal/agent/network_windows.go`
- Modify: `internal/agent/controller.go`
- Modify: `internal/agent/controller_test.go`

**Monitor construction:**

```go
type monitorClock interface {
    NewTicker(time.Duration) ticker
}

type networkMonitorConfig struct {
    FingerprintInterval time.Duration // production: 30s
    AuditInterval       time.Duration // production: 5m
}
```

- [ ] **Step 1: Write failing deterministic-clock tests.** Before connected, assert zero fingerprint/audit calls. While connected and unchanged, 100 fingerprint ticks cause zero PowerShell writes. A changed fingerprint first enables Emergency, emits `network_changed`, then triggers controller stop/restore. An audit mismatch follows the same ordering with `firewall_verify_failed`.
- [ ] **Step 2: Add cancellation/generation tests.** Disconnect waits for monitor exit; a canceled old generation cannot write Emergency or report into a new generation; simultaneous process exit and monitor failure produces one restoration transaction.
- [ ] **Step 3: Run RED tests.**

```powershell
& $go test ./internal/agent -run 'Test(NetworkMonitor|ControllerMonitor)' -count=1
```

- [ ] **Step 4: Implement the monitor.** Fingerprint comparisons use only native APIs. Deep audit is read-only PowerShell unless a failure requires Emergency. Send exactly one buffered terminal error and close the channel. Do not loop on a failed audit.
- [ ] **Step 5: Update Controller lifecycle handling.** Treat core exit, network change, or firewall audit failure as one generation-owned automatic restoration request. Publish the restored `prepared` status with the causal error; rebuild prepared state only after ordinary networking is restored.
- [ ] **Step 6: Run repetition/race and commit.**

```powershell
& $go test ./internal/agent -run 'Test(NetworkMonitor|ControllerMonitor)' -count=50
& $go test -race ./internal/agent -run 'Test(NetworkMonitor|ControllerMonitor)' -count=10
git add internal/agent/network_monitor.go internal/agent/network_monitor_test.go internal/agent/network_windows.go internal/agent/controller.go internal/agent/controller_test.go
git commit -m "feat(windows): monitor only active prepared connections"
```

---

### Task 8: Replace generic logs with the six-step business timeline

**Files:**

- Modify: `internal/traceevent/event.go`
- Modify: `internal/traceevent/event_test.go`
- Modify: `internal/agent/network_windows.go`
- Modify: `internal/agent/network_windows_test.go`
- Modify: `cmd/overseas-client/viewmodel.go`
- Modify: `cmd/overseas-client/viewmodel_test.go`
- Modify: `cmd/overseas-client/traceview.go`
- Modify: `cmd/overseas-client/traceview_test.go`
- Modify: `cmd/overseas-client/main_windows.go`

**Required user-facing messages:**

- `正在读取当前网络配置 / 当前网络配置已确认`
- `正在枚举需要保护的网卡 / 已识别 N 个需保护接口`
- `正在创建预置防泄漏规则 / 预置规则已准备并保持禁用`
- `正在启用防泄漏保护 / 防泄漏保护已启用，共 N 条规则`
- `正在核对 Windows 防火墙活动状态 / 活动规则核对通过`
- `正在等待 sing-box TUN 网卡 / TUN 网卡已就绪`
- `正在切换 DNS 与安全路由 / 安全路由已启用`
- `正在恢复普通网络 / 普通网络已恢复`
- `正在检查连接残留 / 活动残留已清零`

- [ ] **Step 1: Write failing text-contract tests.** Reject `开始执行固定网络操作`, `固定网络操作完成`, raw operation codes as the primary line, firewall errors shown as TUN errors, and a failed generation that omits its automatic-restore events.
- [ ] **Step 2: Write failing ViewModel tests.** Require top status `业务阶段 · x.x 秒 · 第 n/6 步`, default-expanded diagnostics, live elapsed time, `prepared` with a last-attempt error and enabled Retry, `preparing` disabled Connect, and `failed_safe` IT-only recovery guidance.
- [ ] **Step 3: Run RED tests.**

```powershell
& $go test ./internal/traceevent ./internal/agent ./cmd/overseas-client -run 'Test.*(BusinessMessage|Timeline|Prepared|Phase|AutomaticRestore)' -count=1
```

- [ ] **Step 4: Centralize operation metadata.** Each operation code maps to one fixed stage, start text, success formatter, and safe technical-detail formatter. Details include generation, prepared generation, adapter/rule counts, GUID, elapsed time, and redacted error class only.
- [ ] **Step 5: Implement UI rendering.** Keep logs expanded in v18 debug builds. Render the current operation independently from historical rows so status polling cannot erase the timeline. Include prepared-generation and final active/Disabled residue counts in copied diagnostics.
- [ ] **Step 6: Run focused UI/trace regressions and commit.**

```powershell
& $go test ./internal/traceevent ./internal/agent ./cmd/overseas-client -count=1
git add internal/traceevent internal/agent/network_windows.go internal/agent/network_windows_test.go cmd/overseas-client
git commit -m "feat(ui): show precise prepared connection timeline"
```

---

### Task 9: Prepare automatically at service start and preserve the pool across install/upgrade

**Files:**

- Modify: `cmd/overseas-agent/main_windows.go`
- Modify: `cmd/overseas-agent/main_windows_test.go`
- Modify: `deploy/client/Files.wxs`
- Modify: `deploy/client/install-client.ps1`
- Modify: `tests/powershell/ClientInstall.Tests.ps1`
- Modify: `tests/powershell/ClientNetworkTransaction.Tests.ps1`

**Service lifecycle:** After startup recovery proves active residue zero, report SCM Running, start the pipe, and launch one background `Prepare`. A Connect arriving during preparation joins the same preparation result. MSI installs the service as `Start="auto"` and uses `ServiceControl Start="install"`; upgrade and uninstall still stop/wait first.

- [ ] **Step 1: Write failing service tests.** Assert recovery precedes pipe/prepare, SCM is not blocked for the full cold preparation, background preparation errors become `failed_safe` only when Emergency/ownership cannot be proved, and Stop waits for preparation/monitor/restore goroutines.
- [ ] **Step 2: Update Pester expectations to RED.** Require automatic service start, prepared and ledger files under the protected data root, valid Disabled prepared rules allowed after install/repair, active rules still forbidden, and exact owned-rule removal on uninstall after full result materialization.
- [ ] **Step 3: Run RED tests.**

```powershell
& $go test ./cmd/overseas-agent -run 'TestService.*(Prepare|Recovery|Stop)' -count=1
powershell.exe -NoProfile -Command "$r=Invoke-Pester -Script @('tests/powershell/ClientInstall.Tests.ps1','tests/powershell/ClientNetworkTransaction.Tests.ps1') -PassThru; if($r.FailedCount){exit 1}"
```

- [ ] **Step 4: Implement service and WiX changes.** Do not start the service until all signed payload and policy files are installed. Preserve the existing service recovery configuration. Install/repair assertions distinguish exact Disabled owned prepared rules from Enabled residue or unknown group members.
- [ ] **Step 5: Harden uninstall.** Request controlled restore, prove no active transaction/process/TUN/routes, materialize exact ledger-owned rule names, delete them one by one, then delete ledger/prepared files. Unknown or drifted group members fail uninstall rather than being wildcard-deleted.
- [ ] **Step 6: Run dual GREEN tests and commit.**

```powershell
& $go test ./cmd/overseas-agent -count=1
powershell.exe -NoProfile -Command "$r=Invoke-Pester -Script @('tests/powershell/ClientInstall.Tests.ps1','tests/powershell/ClientNetworkTransaction.Tests.ps1') -PassThru; if($r.FailedCount){exit 1}"
pwsh -NoProfile -Command "$r=Invoke-Pester -Path 'tests/powershell/ClientInstall.Tests.ps1','tests/powershell/ClientNetworkTransaction.Tests.ps1' -PassThru; if($r.FailedCount){exit 1}"
git add cmd/overseas-agent deploy/client/Files.wxs deploy/client/install-client.ps1 tests/powershell/ClientInstall.Tests.ps1 tests/powershell/ClientNetworkTransaction.Tests.ps1
git commit -m "feat(installer): keep prepared firewall pool ready"
```

---

### Task 10: Prove recovery, LocalSystem behavior, and timing without masking failures

**Files:**

- Modify: `internal/agent/network_windows_integration_test.go`
- Modify: `tests/powershell/ClientNetworkTransaction.Tests.ps1`
- Create: `scripts/windows/verify-v18-prepared-connection.ps1`
- Create: `tests/powershell/PreparedConnectionGate.Tests.ps1`
- Modify: `docs/poc-runbook.md`

**Evidence output:** `build/v18-evidence/<UTC>/` contains redacted JSON for preflight inventory, LocalSystem rule preparation, enable/verify/disable timings, three simulated transaction timings, recovery result, and final residue. The script refuses to run without elevation, the exact installed signer, a stopped/non-transitioning client, and an explicit `-LiveProductFirewallGate` switch.

- [ ] **Step 1: Write failing static and dry-run gate tests.** Require exact product paths/rule group, no wildcard delete, no proxy/FlClash mutation, query materialization, run-owned evidence directory, cleanup in `finally`, and rejection if foreign product-group rules exist.
- [ ] **Step 2: Add privileged integration cases behind the existing live guard.** Prove legacy fixed rules and a 23-rule fixture are materialized and individually disabled/removed; a valid ten-rule prepared pool survives disconnect Disabled; LocalSystem can prepare, enable, verify, disable, and audit it; cancellation cannot leave enabled rules.
- [ ] **Step 3: Add performance instrumentation assertions.** Every trace pair has non-negative elapsed time. In a prepared fixture: fingerprint/snapshot ≤500 ms, enable+verify ≤3 s, core/TUN fixture ≤5 s, route fixture ≤2 s, total ≤15 s. A cold topology rebuild has a separate ≤30 s budget and emits `preparing` rather than TUN failure.
- [ ] **Step 4: Run non-live tests and observe RED, then implement the gate.**

```powershell
Remove-Item Env:OVERSEAS_ACCESS_INTEGRATION -ErrorAction SilentlyContinue
& $go test ./internal/agent ./tests/integration/... -count=1
powershell.exe -NoProfile -Command "$r=Invoke-Pester -Script 'tests/powershell/PreparedConnectionGate.Tests.ps1' -PassThru; if($r.FailedCount){exit 1}"
```

- [ ] **Step 5: Run the guarded LocalSystem/firewall gate only after source tests are GREEN and the live product inventory is exact.** Record, but do not fabricate, the measured stage timings. If any stable prepared cycle exceeds 15 seconds, stop release work and optimize the measured stage; do not raise the limit.
- [ ] **Step 6: Re-run non-live tests, review evidence for secrets, and commit.**

```powershell
& $go test ./internal/agent ./tests/integration/... -count=1
powershell.exe -NoProfile -Command "$r=Invoke-Pester -Script 'tests/powershell/PreparedConnectionGate.Tests.ps1' -PassThru; if($r.FailedCount){exit 1}"
pwsh -NoProfile -Command "$r=Invoke-Pester -Path 'tests/powershell/PreparedConnectionGate.Tests.ps1' -PassThru; if($r.FailedCount){exit 1}"
git add internal/agent/network_windows_integration_test.go tests/powershell/ClientNetworkTransaction.Tests.ps1 scripts/windows/verify-v18-prepared-connection.ps1 tests/powershell/PreparedConnectionGate.Tests.ps1 docs/poc-runbook.md
git commit -m "test(windows): gate prepared recovery and connection timing"
```

---

### Task 11: Run the complete non-live release gate

**Files:**

- Modify if required by verified failures only: `scripts/windows/build-client-artifacts.ps1`
- Modify if required by verified failures only: `scripts/windows/inspect-client-msi.ps1`
- Modify if required by verified failures only: `scripts/windows/publish-client-release.ps1`
- Create: `docs/superpowers/reports/2026-09-02-v18-prepared-firewall-fast-connect-verification.md`

- [ ] **Step 1: Run formatting, full Go tests, race, vet, and repetition.**

```powershell
$go = 'C:\Users\Eleme\codex_workspace\.tools\go1.27.0\go\bin\go.exe'
& $go fmt ./...
& $go test ./... -count=1
& $go test -race ./internal/agent ./internal/coreverify ./internal/clientapi ./cmd/overseas-client -count=1
& $go test ./internal/agent -run 'TestController|TestWindowsNetwork|TestNetworkMonitor' -count=20
& $go vet ./...
```

Expected: all exit 0; no race report; no live network mutation.

- [ ] **Step 2: Run the complete Pester suites in Windows PowerShell 5.1 and PowerShell 7.**

```powershell
powershell.exe -NoProfile -Command "$r=Invoke-Pester -Script 'tests/powershell' -PassThru; if($r.FailedCount){exit 1}"
pwsh -NoProfile -Command "$r=Invoke-Pester -Path 'tests/powershell' -PassThru; if($r.FailedCount){exit 1}"
```

- [ ] **Step 3: Parse every PowerShell file with the Windows PowerShell 5.1 AST and build Windows binaries.**

```powershell
$parseErrors = @()
Get-ChildItem -Recurse -File -Include *.ps1,*.psm1 | ForEach-Object { $tokens = $null; $fileErrors = $null; [void][Management.Automation.Language.Parser]::ParseFile($_.FullName,[ref]$tokens,[ref]$fileErrors); $parseErrors += @($fileErrors) }
if ($parseErrors.Count) { $parseErrors | Format-List; throw 'PowerShell AST parse failed' }
$env:PATH = 'C:\msys64\ucrt64\bin;' + $env:PATH
& $go generate ./cmd/overseas-client
& $go build -trimpath -o bin/overseas-agent.exe ./cmd/overseas-agent
& $go build -trimpath -ldflags '-H windowsgui' -o bin/overseas-client.exe ./cmd/overseas-client
```

- [ ] **Step 4: Inspect source hygiene and the release diff.**

```powershell
rg -n "开始执行固定网络操作|固定网络操作完成|protectionInterval|250 \* time.Millisecond|Get-NetFirewallRule.*\|.*Remove-NetFirewallRule" internal cmd deploy scripts tests
git diff --check
git status --short
```

Expected: the first search has no production hits; diff check passes; only the verification report is uncommitted before its commit.

- [ ] **Step 5: Write the verification report.** Record exact commands, pass/fail counts, measured prepared/cold timings, active and Disabled residue semantics, current commit, tool versions, and any consciously skipped live gate. Do not claim real overseas browsing success.
- [ ] **Step 6: Commit the report and require a clean tree.**

```powershell
git add docs/superpowers/reports/2026-09-02-v18-prepared-firewall-fast-connect-verification.md
git commit -m "docs: record v18 prepared connection verification"
git status --short
```

---

### Task 12: Publish, inspect, install, and hand off the real acceptance test

**Files:**

- Generated only: `dist/OverseasAccessSetup-v18-RELEASE_SIGNED.msi`
- Generated only: `build/v18-release-*`
- Update after measured results: `docs/superpowers/reports/2026-09-02-v18-prepared-firewall-fast-connect-verification.md`

- [ ] **Step 1: Publish from a clean committed tree using the PoC signing certificate.**

```powershell
& .\scripts\windows\publish-client-release.ps1 `
  -SigningCertificateThumbprint '6A9D8BC41086C6B764B8C7439E797671EF83C15E' `
  -SignToolPath 'C:\Program Files (x86)\Windows Kits\10\bin\10.0.26100.0\x64\signtool.exe' `
  -FinalMsiPath 'dist/OverseasAccessSetup-v18-RELEASE_SIGNED.msi'
```

- [ ] **Step 2: Inspect before installation.** Require valid MSI and first-party Authenticode signatures, exact signer thumbprint, a new ProductCode, exact payload allowlist, automatic service metadata, no credential/proxy material, and source-to-package hash equality. Record MSI SHA-256 and ProductCode.
- [ ] **Step 3: Inventory the current machine before mutation.** Record exact RegenBio ProductCodes, service state/PID, `network-state.json`, prepared/ledger presence, exact managed-group rules with Enabled state, product routes/TUN/core processes, and current connectivity. Stop if unknown group members or non-product collisions exist.
- [ ] **Step 4: Upgrade/install silently with verbose MSI logging.** Require one registered product, service Running, `prepared` within the 30-second cold budget, normal and Emergency rules Disabled, active snapshot/routes/TUN/core zero, and prepared-rule count consistent with the current protected adapters.
- [ ] **Step 5: Run three service-side prepared preflight cycles without overseas browsing.** Each must enable/verify/disable exact owned rules under the guarded test action, leave zero active residue, and meet the ≤15-second stable transaction budget. This does not substitute for the user's real TUN test.
- [ ] **Step 6: Hand off the real user test.** Ask the user to fully exit FlClash, click Connect, and report the displayed timeline. The user verifies approved overseas sites, internal sites, and `172.20.9.15`; then clicks Disconnect. Do not click for the user.
- [ ] **Step 7: Collect final evidence.** Require three real stable connections ≤15 seconds, ordinary network restored after each Disconnect, no enabled product rules while prepared, zero active residue, correct `network_changed` behavior, and a killed-core automatic restore with no public direct leak. If any gate fails, preserve logs and return to the exact failing task rather than publishing a timeout increase.

---

## Specification Coverage Review

- Prepared Disabled rule pool, per-adapter Any rules, DNS rules, Emergency separation, ledger ownership: Tasks 1, 4, 5, 9.
- Native baseline, fingerprint, node routes, prepared generation: Tasks 2 and 5.
- Binary verification cache bound to file and trust evidence: Task 3.
- Fail-closed fast connection ordering and ≤15-second stable budget: Tasks 5, 6, 10, 12.
- Automatic reverse-order restore and zero active residue: Tasks 6, 7, 9, 10.
- Post-connected-only 30-second fingerprint and 5-minute audit: Task 7.
- Accurate error boundaries and no false TUN diagnosis: Tasks 1, 6, 8.
- Default-expanded detailed Chinese timeline and copied diagnostics: Task 8.
- Service startup preparation, upgrade/uninstall, LocalSystem recovery: Tasks 9 and 10.
- Full Go/race/vet/Pester/AST/signature/MSI and real user acceptance gates: Tasks 11 and 12.

No implementation step changes VM101 or the telecom listener. No step removes fail-closed protection, raises the 15-second limit, or treats Disabled prepared rules as active residue.
