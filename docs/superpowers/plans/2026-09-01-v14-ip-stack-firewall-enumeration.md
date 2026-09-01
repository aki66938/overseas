# v14 Windows IP-Stack Firewall Enumeration Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace NDIS-wide adapter discovery with IP-stack-backed discovery, verify every published firewall rule, expose bounded failure diagnostics, and deploy a locally proven signed v14 client.

**Architecture:** `scanNetworkPowerShell` starts with `Get-NetIPInterface`, deduplicates positive interface indices, and joins each index to exactly one `Get-NetAdapter` identity. The manager excludes only its exact owned TUN, publishes per-interface rules, then runs a separate ActiveStore verification operation. Fixed PowerShell failures carry a bounded sanitized detail into the diagnostics endpoint while the stable user-facing error code remains unchanged.

**Tech Stack:** Go 1.27, Windows PowerShell 5.1, PowerShell 7/Pester 3.4, Windows Firewall CIM cmdlets, WiX 4.0.6, Authenticode/CMS.

## Global Constraints

- Do not filter by adapter name, description, vendor, WAN Miniport label, Hyper-V label, or localized Alias.
- A protected identity remains `InterfaceIndex + InterfaceGuid + InterfaceAlias + Status`.
- Exclude the product TUN only when Index, GUID, and Alias all match its validated owned identity.
- Any ambiguous/incomplete IP-to-adapter join, firewall publication failure, or ActiveStore verification failure remains fail-closed.
- Keep client error code `public_tcp_block_failed` and Chinese user message unchanged.
- Diagnostic detail is fixed-operation output only, strips control characters, is whitespace-normalized, and is capped at 512 UTF-8 bytes.
- Do not modify VM101, telecom client, FlClash, macOS/Linux scope, AD authorization, or load balancing.

---

### Task 1: Discover only firewall-bindable IP-stack adapters

**Files:**
- Modify: `internal/agent/network_windows.go:1149-1160`
- Modify: `internal/agent/network_windows_test.go:513-556`

**Interfaces:**
- Consumes: Windows `Get-NetIPInterface` and `Get-NetAdapter -IncludeHidden -InterfaceIndex`.
- Produces: the existing JSON array `[]WindowsAdapterIdentity` consumed by `reconcileProtection`.

- [ ] **Step 1: Write the failing scan-contract tests**

Add assertions requiring the script to contain `Get-NetIPInterface`, `Sort-Object -Unique`, `Get-NetAdapter -IncludeHidden -InterfaceIndex`, and the prefix `adapter_identity_join:`. Forbid the old `Where-Object Status -ne 'Not Present'`, `WAN Miniport`, and `InterfaceDescription` filters.

- [ ] **Step 2: Run the focused test and observe RED**

```powershell
$env:GOTOOLCHAIN='local'
& 'C:\Users\Eleme\codex_workspace\.tools\go1.27.0\go\bin\go.exe' test ./internal/agent -run TestWindowsNetworkProtectionCoversRASAndHotPluggedAdaptersByIdentity -count=1
```

Expected: FAIL with `adapter scan is not rooted in the Windows IP stack`.

- [ ] **Step 3: Replace the scan script with the minimal IP-stack join**

```powershell
$indices = @(Get-NetIPInterface | Where-Object { [int]$_.InterfaceIndex -gt 0 } |
  Select-Object -ExpandProperty InterfaceIndex | Sort-Object -Unique)
$adapters = @()
foreach ($index in $indices) {
  $matches = @(Get-NetAdapter -IncludeHidden -InterfaceIndex ([int]$index) -ErrorAction SilentlyContinue)
  if ($matches.Count -eq 0) { continue }
  if ($matches.Count -ne 1) { throw 'adapter_identity_join: IP interface did not resolve to exactly one adapter.' }
  $adapter = $matches[0]
  if ([int]$adapter.InterfaceIndex -le 0 -or [string]::IsNullOrWhiteSpace([string]$adapter.InterfaceGuid) -or [string]::IsNullOrWhiteSpace([string]$adapter.InterfaceAlias)) {
    throw 'adapter_identity_join: adapter identity is incomplete.'
  }
  $adapters += [pscustomobject]@{
    InterfaceIndex = [int]$adapter.InterfaceIndex
    InterfaceGuid = [string]$adapter.InterfaceGuid
    InterfaceAlias = [string]$adapter.InterfaceAlias
    Status = [string]$adapter.Status
  }
}
ConvertTo-Json -InputObject @($adapters) -Compress -Depth 4
```

- [ ] **Step 4: Run focused and package tests GREEN**

Run the focused command from Step 2, then:

```powershell
& 'C:\Users\Eleme\codex_workspace\.tools\go1.27.0\go\bin\go.exe' test ./internal/agent -count=1
```

Expected: both commands exit 0.

- [ ] **Step 5: Commit Task 1**

```powershell
git add internal/agent/network_windows.go internal/agent/network_windows_test.go
git commit -m "fix(windows): enumerate firewall adapters from IP stack"
```

---

### Task 2: Verify the published ActiveStore rule set

**Files:**
- Modify: `internal/agent/network_windows.go`
- Modify: `internal/agent/network_windows_test.go`

**Interfaces:**
- Produces: `networkOperationVerify = "verify"` and `verifyNetworkPowerShell` consuming the same `windowsNetworkInput` passed to block.
- Changes `reconcileProtection` order to `scan -> block -> verify`.

- [ ] **Step 1: Write failing order and script-contract tests**

Add a test that calls `InstallPublicTCPBlock`, asserts the runner trace is `capture, save, save, scan, block, verify`, and asserts `verifyNetworkPowerShell` uses `Get-NetFirewallRule -PolicyStore ActiveStore`, `Get-NetFirewallInterfaceFilter`, `Get-NetFirewallAddressFilter`, and `Get-NetFirewallPortFilter`.

- [ ] **Step 2: Run the focused test and observe RED**

```powershell
$env:GOTOOLCHAIN='local'
& 'C:\Users\Eleme\codex_workspace\.tools\go1.27.0\go\bin\go.exe' test ./internal/agent -run TestWindowsNetworkCapturePersistsExactStateBeforeMutation -count=1
```

Expected: FAIL because the trace ends at `block`.

- [ ] **Step 3: Add the verify operation and exact verifier**

Add `networkOperationVerify`, register its fixed script, and call it immediately after a successful block operation. The verifier enumerates every expected GUID-derived TCP/QUIC/UDP rule plus the two DNS rules, requires exactly one ActiveStore rule per name, requires product group/Outbound/Block/Enabled, and verifies the expected interface alias, protocol, port, and remote-address set. Every throw begins with `active_store_verify:`.

- [ ] **Step 4: Run focused and package tests GREEN**

Run Step 2 and then `go test ./internal/agent -count=1`. Expected: both exit 0.

- [ ] **Step 5: Commit Task 2**

```powershell
git add internal/agent/network_windows.go internal/agent/network_windows_test.go
git commit -m "fix(windows): verify kill-switch rules in ActiveStore"
```

---

### Task 3: Preserve bounded network failure diagnostics

**Files:**
- Modify: `internal/agent/network_windows.go`
- Modify: `internal/agent/controller.go`
- Modify: `internal/agent/controller_test.go`
- Modify: `internal/agent/pipe_windows_test.go`
- Modify: `internal/clientapi/client.go`
- Modify: `internal/clientapi/client_test.go`
- Modify: `cmd/overseas-client/viewmodel_test.go`

**Interfaces:**
- Produces: `Diagnostics.Stage string` with JSON `stage,omitempty` and `Diagnostics.Detail string` with JSON `detail,omitempty` in agent/client API types.
- Produces: a typed fixed-operation error whose stage is one of `ip_interface_scan`, `adapter_identity_join`, `firewall_publish`, `active_store_verify`, or `emergency_protection`.

- [ ] **Step 1: Write RED tests for sanitization and diagnostics transport**

Test that a runner error containing control characters and 1,000 bytes is reduced to one line of at most 512 UTF-8 bytes, excludes a secret-like input payload, and retains the stable `public_tcp_block_failed` error code. Extend pipe/client round-trip tests to accept only `stage` and `detail` as the new fields.

- [ ] **Step 2: Run focused RED tests**

```powershell
$env:GOTOOLCHAIN='local'
& 'C:\Users\Eleme\codex_workspace\.tools\go1.27.0\go\bin\go.exe' test ./internal/agent ./internal/clientapi -run 'Diagnostics|PowerShellNetworkRunner' -count=1
```

Expected: FAIL because diagnostic stage/detail do not exist and stderr is discarded.

- [ ] **Step 3: Implement minimal typed diagnostics**

Capture stderr in `powerShellNetworkRunner.Run`, normalize Unicode control and whitespace, cap to 512 UTF-8 bytes, and return it only inside a typed fixed-operation error. Map scan errors containing `adapter_identity_join:` to that stage; otherwise map fixed operations to approved stages. Clear diagnostics at the start of a new generation. On a connection failure, publish only the typed stage/detail in `Controller.Diagnostics`; never replace user-facing `Status.Message`.

- [ ] **Step 4: Run focused and full package tests GREEN**

Run Step 2, then:

```powershell
& 'C:\Users\Eleme\codex_workspace\.tools\go1.27.0\go\bin\go.exe' test ./internal/agent ./internal/clientapi ./cmd/overseas-client -count=1
```

Expected: all exit 0.

- [ ] **Step 5: Commit Task 3**

```powershell
git add internal/agent/network_windows.go internal/agent/controller.go internal/agent/controller_test.go internal/agent/pipe_windows_test.go internal/clientapi/client.go internal/clientapi/client_test.go cmd/overseas-client/viewmodel_test.go
git commit -m "feat(windows): expose bounded kill-switch diagnostics"
```

---

### Task 4: Add and run the LocalSystem pre-publication gate

**Files:**
- Create: `scripts/windows/verify-client-firewall-interfaces.ps1`
- Create: `tests/powershell/ClientFirewallInterfaces.Tests.ps1`

**Interfaces:**
- Script parameters: `-EvidencePath`, an absolute create-new JSON path.
- Output: evidence containing service account identity, expected adapter identities, per-adapter temporary-rule results, and zero-residue assertions; no secrets or full route/config dumps.

- [ ] **Step 1: Write failing Pester safety tests**

Require Windows PowerShell 5.1 syntax, elevation and LocalSystem refusal gates, fixed `RegenBio.Diagnostic.Preflight.<GUID>` names, RFC documentation addresses only, `try/finally` cleanup, create-new evidence, and exact zero-residue checks.

- [ ] **Step 2: Run dual RED Pester tests**

```powershell
powershell.exe -NoProfile -Command "$r=Invoke-Pester -Script tests/powershell/ClientFirewallInterfaces.Tests.ps1 -PassThru; if($r.FailedCount){exit 1}"
& 'C:\Users\Eleme\.cache\codex-runtimes\codex-primary-runtime\dependencies\native\powershell\pwsh.exe' -NoProfile -Command '$r=Invoke-Pester -Script tests/powershell/ClientFirewallInterfaces.Tests.ps1 -PassThru; if($r.FailedCount){exit 1}'
```

Expected: both fail because the gate script is absent.

- [ ] **Step 3: Implement the fixed LocalSystem gate**

The script independently performs the approved IP-stack join, creates one temporary TCP rule per discovered interface against `192.0.2.1/32` and `2001:db8::1/128`, reads it back from ActiveStore including the interface filter, deletes it in `finally`, and refuses success if any diagnostic/product rule, product route, product TUN, or network snapshot remains. It never starts a connection or changes FlClash.

- [ ] **Step 4: Run dual GREEN Pester tests and execute as LocalSystem**

Run Step 2. Launch the gate through a temporary LocalSystem service, wait for its create-new evidence file, delete only that temporary service, and verify every interface result is successful and residue counts are zero.

- [ ] **Step 5: Commit Task 4**

```powershell
git add scripts/windows/verify-client-firewall-interfaces.ps1 tests/powershell/ClientFirewallInterfaces.Tests.ps1
git commit -m "test(windows): add LocalSystem firewall interface gate"
```

---

### Task 5: Full verification, signed v14 build, clean upgrade, and handoff

**Files:**
- Create: `dist/OverseasAccessSetup-POC-DIRECT-HTTP-v14-RELEASE_SIGNED.msi` (ignored release artifact)
- Verify: `C:\Program Files\RegenBio\OverseasAccess`
- Verify: `C:\ProgramData\RegenBio\OverseasAccess`

**Interfaces:**
- Release signer: `6A9D8BC41086C6B764B8C7439E797671EF83C15E`.
- Release publisher: `scripts/windows/publish-client-release.ps1`.

- [ ] **Step 1: Run repository verification**

Run locked Go `test ./... -count=1`, `vet ./...`, both complete Pester suites, all PowerShell AST parses under Windows PowerShell 5.1, Windows amd64 client builds, and `git diff --check`. Expected: every command exits 0.

- [ ] **Step 2: Build and verify signed v14**

Commit verification-only source changes first so the release worktree is clean. Publish v14 with the approved thumbprint and x64 Windows SDK `signtool.exe`. Verify MSI Authenticode, SHA-256, embedded manifest source commit, and extracted first-party binary hashes/signatures.

- [ ] **Step 3: Reconcile installed MSI product state**

Inventory exact RegenBio ProductCodes. If v13 is the sole product, stop the service, prove no snapshot/TUN/product routes/managed rules, uninstall v13 normally, and prove zero product registrations and residue. Refuse wildcard registry/service/file deletion.

- [ ] **Step 4: Install v14 and run non-connected verification**

Install v14 silently with verbose logging. Require exactly one ProductCode, signed installed binaries matching the signed manifest, service `Running`, and zero snapshot, managed rules, product routes, and product TUN before user action. Re-run the LocalSystem pre-publication gate against installed artifacts.

- [ ] **Step 5: User acceptance handoff**

Ask the user to fully exit FlClash, click connect once, and return copied diagnostics. Do not claim the end-to-end path fixed until state is `connected` and the user confirms approved overseas access, corporate access, and clean disconnect recovery.

