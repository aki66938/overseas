# v12 Windows Kill-Switch Recovery Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the incompatible loopback sink-route layer with a verified Windows firewall kill-switch and make snapshot recovery safe across adapter index changes.

**Architecture:** `WindowsNetworkManager` will persist stable adapter GUIDs and explicit ownership phases. Connection protection becomes `capture -> protected intent -> adapter scan -> firewall publish/verify`, while route publication remains after sing-box readiness. Recovery is phase-aware: captured/protected snapshots never rewrite untouched interface settings; TUN-owned snapshots resolve current interface indices from exact GUIDs before restoring.

**Tech Stack:** Go 1.27, Windows PowerShell 5.1 fixed scripts, Windows Filtering Platform cmdlets, sing-box 1.13.19, WiX 4.0.6, Pester 3.4/PowerShell 7.

## Global Constraints

- Do not modify VM101, the telecom client, or its `[::]:8080` listener.
- Do not create metric 8192 sink routes or claim zero-gap protection against arbitrary privileged routes.
- The firewall kill-switch must be verified in `ActiveStore` before the core starts.
- Corporate CIDRs/DNS and `172.20.9.15` remain outside public blocking and outside the TUN route.
- Recovery deletes only exact product-owned routes/rules and retains the snapshot on ambiguity or failure.
- Use strict RED -> GREEN TDD for every production behavior change.

---

### Task 1: Remove Guard Routes and Persist the Protected Phase

**Files:**
- Modify: `internal/agent/network_windows.go`
- Modify: `internal/agent/network_windows_test.go`
- Modify: `internal/agent/controller_test.go`

**Interfaces:**
- Consumes: `WindowsNetworkManager.Capture`, `InstallPublicTCPBlock`, `ActivateTUNRoutes`, `Restore`.
- Produces: `windowsSnapshotPhaseProtected = "protected"`; connection protection with no `networkOperationGuard`; snapshots with no `GuardRoutes`.

- [ ] **Step 1: Write failing tests for the v12 operation order and ownership model**

Add focused tests that assert:

```go
func TestWindowsNetworkProtectionPublishesFirewallWithoutGuardRoutes(t *testing.T) {
    runner := &fakeNetworkRunner{capture: validWindowsSnapshot()}
    store := &fakeSnapshotStore{}
    manager, err := newWindowsNetworkManager(validPolicy(), `C:\state.json`, runner, store)
    if err != nil { t.Fatal(err) }
    if _, err := manager.Capture(context.Background()); err != nil { t.Fatal(err) }
    if _, err := manager.InstallPublicTCPBlock(context.Background()); err != nil { t.Fatal(err) }
    if got, want := runner.operations, []string{"capture", "scan", "block"}; !equalStrings(got, want) {
        t.Fatalf("operations = %v, want %v", got, want)
    }
    if len(store.snapshot.GuardRoutes) != 0 || store.snapshot.OwnershipPhase != windowsSnapshotPhaseProtected {
        t.Fatalf("protected snapshot = %#v", store.snapshot)
    }
}
```

Update activation expectations so owned routes contain only TUN public IPv4 routes and required node bypass routes, never guard routes. Add a controller ordering assertion proving `InstallPublicTCPBlock` completes before `process.Start`.

- [ ] **Step 2: Run the focused RED tests**

Run:

```powershell
& 'C:\Users\Eleme\codex_workspace\.tools\go1.27.0\go\bin\go.exe' test -count=1 ./internal/agent -run 'ProtectionPublishesFirewallWithoutGuardRoutes|ActivateUsesFixedTUNRoutes|Connect'
```

Expected: FAIL because `guard` is still called, guard routes remain persisted/carried, and no protected phase exists.

- [ ] **Step 3: Implement the minimal no-guard protection flow**

In `network_windows.go`:

```go
const (
    windowsSnapshotPhaseCaptured  = "captured"
    windowsSnapshotPhaseProtected = "protected"
    windowsSnapshotPhaseTUNOwned  = "tun-owned"
)
```

Remove `networkOperationGuard`, `windowsGuardRouteMetric`, guard-route generation in `Capture`, the guard call in `InstallPublicTCPBlock`, guard promotion in `ActivateTUNRoutes`, and `guardNetworkPowerShell` from the fixed script map. Before the first firewall mutation, set `m.current.OwnershipPhase = windowsSnapshotPhaseProtected`, reseal it, and save it. If saving fails, do not call scan/block. Keep `reconcileProtection` responsible for scan followed by firewall publication/verification.

Update snapshot validation so `captured` and `protected` require zero `GuardRoutes`; `protected` permits no TUN ownership; `tun-owned` validates only exact TUN routes.

- [ ] **Step 4: Run focused GREEN tests**

Run the command from Step 2 plus:

```powershell
& 'C:\Users\Eleme\codex_workspace\.tools\go1.27.0\go\bin\go.exe' test -count=1 ./internal/agent
```

Expected: PASS and no trace operation named `guard`.

- [ ] **Step 5: Commit Task 1**

```powershell
git add internal/agent/network_windows.go internal/agent/network_windows_test.go internal/agent/controller_test.go
git commit -m "fix: replace Windows sink routes with firewall protection"
```

---

### Task 2: Make Recovery Phase-Aware and GUID-Stable

**Files:**
- Modify: `internal/agent/network_windows.go`
- Modify: `internal/agent/network_windows_test.go`

**Interfaces:**
- Consumes: persisted `WindowsNetworkSnapshot.OwnershipPhase` and captured adapters.
- Produces: `WindowsInterfaceSnapshot.InterfaceGuid string`; restore input flag `RestoreInterfaces bool`; PowerShell GUID-to-current-index resolution.

- [ ] **Step 1: Write failing captured-only and renumbered-interface tests**

Add tests with these assertions:

```go
func TestCapturedOnlyRestoreDoesNotRewriteInterfaces(t *testing.T) {
    snapshot := capturedWindowsSnapshot(t)
    input := restorationInputForTest(t, snapshot)
    if input.RestoreInterfaces { t.Fatal("captured-only restore rewrites interfaces") }
}

func TestTUNOwnedRestoreCarriesStableInterfaceGUID(t *testing.T) {
    snapshot := fullyOwnedWindowsSnapshotFromCapture(t, validWindowsSnapshot())
    snapshot.Interfaces[0].InterfaceGuid = "{11111111-1111-1111-1111-111111111111}"
    input := restorationInputForTest(t, snapshot)
    if !input.RestoreInterfaces || input.Interfaces[0].InterfaceGuid == "" {
        t.Fatalf("restore input = %#v", input)
    }
}
```

Add fixed-script contract tests requiring `Get-NetAdapter -IncludeHidden`, exact case-insensitive GUID selection, current `InterfaceIndex`, and rejection of zero/multiple matches. Add corruption tests for missing/duplicate GUIDs.

- [ ] **Step 2: Run focused RED tests**

```powershell
& 'C:\Users\Eleme\codex_workspace\.tools\go1.27.0\go\bin\go.exe' test -count=1 ./internal/agent -run 'CapturedOnlyRestore|TUNOwnedRestore|InterfaceGUID'
```

Expected: compile/test failures because `InterfaceGuid` and `RestoreInterfaces` do not exist and restore always uses captured indices.

- [ ] **Step 3: Implement stable identity capture and phase-aware restore**

Extend the data contracts:

```go
type WindowsInterfaceSnapshot struct {
    Index           int      `json:"Index"`
    InterfaceGuid   string   `json:"InterfaceGuid"`
    Alias           string   `json:"Alias"`
    InterfaceMetric int      `json:"InterfaceMetric"`
    AutomaticMetric bool     `json:"AutomaticMetric"`
    DNSAutomatic    bool     `json:"DNSAutomatic"`
    DNSServers      []string `json:"DNSServers"`
}

type windowsNetworkInput struct {
    RestoreInterfaces bool `json:"RestoreInterfaces,omitempty"`
    // existing fields remain
}
```

Capture `[string]$adapter.InterfaceGuid`. Validation requires a non-empty unique GUID for every physical snapshot and rejects the owned TUN GUID. `restorationInput` sets `RestoreInterfaces` only for `tun-owned`.

In `restoreNetworkPowerShell`, wrap interface restoration in `if ([bool]$i.RestoreInterfaces)`. Resolve every snapshot entry using all hidden adapters and a case-insensitive GUID comparison; require exactly one match, reject the owned TUN identity, then use the resolved current index for DNS and metric operations. Captured/protected restore skips this block but still exact-removes product rules/routes and the validated snapshot.

- [ ] **Step 4: Run focused and full agent GREEN tests**

```powershell
& 'C:\Users\Eleme\codex_workspace\.tools\go1.27.0\go\bin\go.exe' test -count=1 ./internal/agent
```

Expected: PASS, including index-renumbering and fail-closed identity cases.

- [ ] **Step 5: Commit Task 2**

```powershell
git add internal/agent/network_windows.go internal/agent/network_windows_test.go
git commit -m "fix: recover Windows adapters by stable identity"
```

---

### Task 3: Diagnostics, Regression Gates, Signed v12 Deployment

**Files:**
- Modify: `internal/agent/controller.go`
- Modify: `internal/agent/controller_test.go`
- Modify: `cmd/overseas-agent/main_windows.go`
- Modify: `cmd/overseas-agent/main_windows_test.go`
- Modify: `.superpowers/sdd/task-10-report.md`
- Generated artifact: `dist/OverseasAccessSetup-POC-DIRECT-HTTP-v12-RELEASE_SIGNED.msi`

**Interfaces:**
- Consumes: v12 network manager, existing diagnostics pipe, PoC signer thumbprint `6A9D8BC41086C6B764B8C7439E797671EF83C15E`.
- Produces: bounded stable network failure stage in diagnostics/SCM; signed v12 MSI installed locally without initiating a connection.

- [ ] **Step 1: Write failing diagnostic-stage tests**

Create controller tests where scan, firewall publication, and ActiveStore verification fail independently. Require public status `public_tcp_block_failed`, while diagnostics retain only one of `adapter_scan`, `firewall_publish`, `firewall_verify`. Add service tests requiring recovery failures to report a stable internal category instead of leaking raw commands, credentials, paths, or config.

- [ ] **Step 2: Run the RED tests**

```powershell
& 'C:\Users\Eleme\codex_workspace\.tools\go1.27.0\go\bin\go.exe' test -count=1 ./internal/agent ./cmd/overseas-agent -run 'Diagnostic|RecoveryFailure'
```

Expected: FAIL because only the generic public error is retained.

- [ ] **Step 3: Implement bounded stage diagnostics**

Introduce a typed internal network-stage error with a closed set of stage constants. Preserve the public status mapping, store only the stable stage and a sanitized/length-bounded reason in `Diagnostics`, and make the service exit/event path use a fixed category. Do not expose stdin payloads, PowerShell source, credential bytes, rendered configuration, or arbitrary command lines.

- [ ] **Step 4: Run the complete non-live verification matrix**

```powershell
$go='C:\Users\Eleme\codex_workspace\.tools\go1.27.0\go\bin\go.exe'
& $go test -count=1 ./...
& $go vet ./...
& powershell.exe -NoProfile -Command "Import-Module Pester; Invoke-Pester tests/powershell -EnableExit"
& pwsh.exe -NoProfile -Command "Invoke-Pester tests/powershell -CI"
& .\scripts\windows\build-client-artifacts.ps1 -Mode Release -OutputDirectory build\v12-payload
```

Expected: all Go/Pester/build commands exit 0. Parse every PowerShell file with the PS 5.1 AST and run `git diff --check`.

- [ ] **Step 5: Commit code and update the report**

```powershell
git add internal/agent cmd/overseas-agent .superpowers/sdd/task-10-report.md
git commit -m "fix: make v12 Windows recovery diagnosable"
```

- [ ] **Step 6: Publish and verify the signed v12 MSI**

With a clean checkout, run:

```powershell
& .\scripts\windows\publish-client-release.ps1 `
  -SigningCertificateThumbprint '6A9D8BC41086C6B764B8C7439E797671EF83C15E' `
  -SignToolPath 'C:\Program Files (x86)\Windows Kits\10\bin\10.0.26100.0\x64\signtool.exe' `
  -FinalMsiPath 'dist/OverseasAccessSetup-POC-DIRECT-HTTP-v12-RELEASE_SIGNED.msi'
```

Require a valid MSI signature, exact signer thumbprint, exact payload allowlist/hashes, schema-v2 HTTP CONNECT policy, and no Shadowsocks credential material.

- [ ] **Step 7: Install v12 without connecting and prove a clean baseline**

Close only `overseas-client.exe`, install with `msiexec /i ... /qn /norestart`, start the Agent, and reopen the client. Do not stop or reconfigure FlClash. Verify before user testing: service `Running`; no `network-state.json`; zero product firewall rules; zero metric 4096/8192 routes; zero product TUN adapters.

- [ ] **Step 8: User live acceptance**

The user closes FlClash, clicks Connect once, waits up to 30 seconds, and returns the status JSON. On success, validate TUN identity, firewall definitions, node bypass, approved overseas access and corporate reachability. On disconnect, prove exact restoration and zero product residue.
