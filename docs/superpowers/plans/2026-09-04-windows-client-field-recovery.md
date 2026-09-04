# Windows Client Field Recovery Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Produce and field-verify a signed Windows client that self-recovers its own phantom Wintun device, does not apply legacy firewall monitoring to the zero-rule PoC, installs the required MITM root through a real MSI upgrade, and remains usable for at least ten minutes.

**Architecture:** Keep recovery inside the Windows network ownership boundary: a fixed, allow-listed operation removes only the exact non-present product Wintun instance before preparation. Make runtime firewall auditing conditional on the current prepared state owning firewall definitions, retain bounded redacted core output for readiness failures, and strengthen release/upgrade verification so the installed MSI identity cannot silently remain at an older build.

**Tech Stack:** Go 1.24, Windows IP Helper/PnP tooling, PowerShell 5.1, WiX Toolset 4, Pester 4, Schannel/curl, Git.

## Global Constraints

- Do not change physical-adapter DNS settings as part of diagnosis or installation.
- Never remove or modify unrelated VPN, Wintun, TAP, or tunnel adapters.
- Preserve fail-closed firewall drift handling for prepared states that own firewall rules.
- Follow red-green-refactor for every production behavior change.
- Release only from a clean Git worktree; sign and hash the final MSI.
- Field acceptance requires normal TLS verification and at least two five-minute monitor intervals.

---

### Task 1: Make Runtime Firewall Monitoring State-Aware

**Files:**
- Modify: `internal/agent/network_monitor.go`
- Test: `internal/agent/network_poc_windows_test.go`

**Interfaces:**
- Consumes: `WindowsPreparedState.Rules`, `WindowsNetworkManager.auditPreparedFirewall`, and `WindowsNetworkManager.installPreparedEmergencyProtection`.
- Produces: `preparedFirewallMonitoringApplies(WindowsPreparedState) bool`, used by the runtime monitor to decide whether firewall audit and emergency protection belong to the current generation.

- [ ] **Step 1: Write the failing zero-rule monitor test**

Add a Windows test that creates a minimal prepared state with `FirewallRuleNames: nil`, advances the fake audit ticker, and asserts that the fixed runner receives no `firewall_audit` or `emergency` operation while the monitor remains alive.

```go
func TestRuntimeMonitorSkipsPreparedFirewallAuditForZeroRulePoc(t *testing.T) {
    manager, runner, clock, prepared := newMonitorTestManager(t)
    preparedState := *manager.prepared
    preparedState.Rules = nil
    manager.prepared = &preparedState

    failures, err := manager.StartMonitor(context.Background(), prepared)
    if err != nil { t.Fatal(err) }
    clock.tickAudit()

    assertNoOperation(t, runner.operations(), networkOperationFirewallAudit)
    select {
    case failure := <-failures:
        t.Fatalf("zero-rule PoC monitor failed: %v", failure)
    default:
    }
}
```

- [ ] **Step 2: Run the test and verify RED**

Run:

```powershell
$env:GOOS='windows'; go test ./internal/agent -run TestRuntimeMonitorSkipsPreparedFirewallAuditForZeroRulePoc -count=1
```

Expected: FAIL because `firewall_audit` is still invoked and delivers `errFirewallAudit`.

- [ ] **Step 3: Write the rule-owning regression test**

Add a second test with a complete canonical prepared-rule set including its emergency rule. Advance the audit ticker, inject membership drift, and assert one audit, one emergency attempt, and one terminal failure.

```go
func TestRuntimeMonitorRetainsFailClosedAuditForOwnedPreparedRules(t *testing.T) {
    manager, runner, clock, prepared := newMonitorTestManager(t)
    manager.prepared.Rules = validPreparedFirewallRules()
    runner.failOperation(networkOperationFirewallAudit, errors.New("membership drift"))

    failures, err := manager.StartMonitor(context.Background(), prepared)
    if err != nil { t.Fatal(err) }
    clock.tickAudit()
    if failure := <-failures; !errors.Is(failure, errFirewallAudit) {
        t.Fatalf("monitor failure = %v", failure)
    }
    assertOperationCount(t, runner.operations(), networkOperationFirewallAudit, 1)
    assertOperationCount(t, runner.operations(), networkOperationEmergency, 1)
}
```

- [ ] **Step 4: Implement the minimal applicability guard**

Add:

```go
func preparedFirewallMonitoringApplies(state WindowsPreparedState) bool {
    return len(state.Rules) > 0
}
```

Create the audit ticker only when the predicate is true, and select on a nil audit channel otherwise. Call `armMonitorEmergency` only for applicable state. Validate the emergency rule list before indexing so malformed rule-owning state returns a typed audit error rather than reaching PowerShell.

- [ ] **Step 5: Verify GREEN and regression coverage**

Run:

```powershell
$env:GOOS='windows'; go test ./internal/agent -run 'TestRuntimeMonitor(Skips|Retains)' -count=1
$env:GOOS='windows'; go test ./internal/agent -count=1
```

Expected: PASS.

- [ ] **Step 6: Commit**

```powershell
git add internal/agent/network_monitor.go internal/agent/network_poc_windows_test.go
git commit -m "fix(agent): scope firewall monitor to owned rules"
```

---

### Task 2: Recover Only the Product-Owned Phantom Wintun Device

**Files:**
- Modify: `internal/agent/network_windows.go`
- Modify: `internal/agent/network_poc_windows.go`
- Test: `internal/agent/network_poc_windows_test.go`

**Interfaces:**
- Consumes: the fixed PowerShell runner and constant `windowsTUNInterface`.
- Produces: operation `tun_recover` and `WindowsNetworkManager.recoverOwnedPhantomTUN(context.Context) error`.

- [ ] **Step 1: Write failing operation-shape tests**

Add tests that inspect the fixed `tun_recover` script and require all four safety predicates: exact alias, `SWD\\WINTUN\\` instance prefix, non-present/phantom status, and absence of a managed sing-box process rooted at `windowsCoreExecutable`. Require exact-instance `pnputil /remove-device`, post-removal absence verification, and rejection of multiple matches.

```go
func TestTunRecoveryScriptIsRestrictedToOneOwnedPhantom(t *testing.T) {
    script := fixedWindowsNetworkScript(networkOperationTUNRecover)
    for _, required := range []string{
        "RegenBioOverseasAccess", "SWD\\WINTUN\\", "CM_PROB_PHANTOM",
        "C:\\Program Files\\RegenBio\\OverseasAccess\\sing-box.exe",
        "pnputil.exe", "/remove-device",
    } {
        if !strings.Contains(script, required) { t.Fatalf("missing %q", required) }
    }
}
```

- [ ] **Step 2: Verify RED**

Run:

```powershell
$env:GOOS='windows'; go test ./internal/agent -run 'TestTunRecovery' -count=1
```

Expected: FAIL because `networkOperationTUNRecover` and its script do not exist.

- [ ] **Step 3: Implement the allow-listed fixed operation**

Add `networkOperationTUNRecover = "tun_recover"`, map it to the TUN readiness diagnostic stage, and add a fixed script branch whose algorithm is:

```powershell
$managed = @(Get-CimInstance Win32_Process -Filter "Name='sing-box.exe'" | Where-Object {
  $_.ExecutablePath -eq 'C:\Program Files\RegenBio\OverseasAccess\sing-box.exe'
})
if ($managed.Count -ne 0) { throw 'tun_recover: managed core is active.' }
$matches = @(Get-PnpDevice -PresentOnly:$false | Where-Object {
  $_.InstanceId -like 'SWD\WINTUN\*' -and
  $_.FriendlyName -eq 'sing-tun Tunnel' -and
  $_.Problem -eq 'CM_PROB_PHANTOM'
})
if ($matches.Count -gt 1) { throw 'tun_recover: ownership is ambiguous.' }
if ($matches.Count -eq 1) {
  & pnputil.exe /remove-device $matches[0].InstanceId
  if ($LASTEXITCODE -ne 0) { throw 'tun_recover: removal failed.' }
}
```

The actual script must also correlate the instance to the configured `RegenBioOverseasAccess` alias using the device/interface GUID recorded by Windows, and verify the exact instance is absent after removal. No wildcard removal is permitted.

- [ ] **Step 4: Invoke recovery before baseline rejection**

At the start of `preparePoc`, call `recoverOwnedPhantomTUN(ctx)` before `Baseline`. If no instance exists, it is a no-op. An active, present, or ambiguous match fails preparation without deletion.

- [ ] **Step 5: Verify GREEN and all network tests**

Run:

```powershell
$env:GOOS='windows'; go test ./internal/agent -run 'TestTunRecovery|Test.*Prepare' -count=1
$env:GOOS='windows'; go test ./internal/agent -count=1
```

Expected: PASS.

- [ ] **Step 6: Commit**

```powershell
git add internal/agent/network_windows.go internal/agent/network_poc_windows.go internal/agent/network_poc_windows_test.go
git commit -m "fix(network): recover owned phantom Wintun"
```

---

### Task 3: Preserve Bounded Redacted Core Readiness Diagnostics

**Files:**
- Modify: `internal/supervisor/process_windows.go`
- Modify: `cmd/overseas-agent/main_windows.go`
- Test: `internal/supervisor/process_windows_test.go`
- Test: `cmd/overseas-agent/main_windows_test.go`

**Interfaces:**
- Consumes: existing `streamRedactor`, `MaxLogBytes`, and supervisor readiness errors.
- Produces: `Process.DiagnosticTail() string` and a staged readiness error containing sanitized core output.

- [ ] **Step 1: Write the failing bounded-redaction test**

Launch the integration fake that writes a known secret plus more than 64 KiB before readiness timeout. Assert the returned diagnostic omits the secret, is bounded by `traceevent.MaxDetailBytes`, and contains the final non-secret readiness warning.

```go
func TestReadyTimeoutReturnsBoundedRedactedCoreTail(t *testing.T) {
    process := newDiagnosticFixtureProcess(t, "secret-token", 70*1024)
    err := process.Ready(context.Background())
    if !errors.Is(err, ErrReadyTimeout) { t.Fatalf("Ready() = %v", err) }
    detail := process.DiagnosticTail()
    if strings.Contains(detail, "secret-token") { t.Fatal("secret leaked") }
    if len(detail) > traceevent.MaxDetailBytes { t.Fatalf("detail too large: %d", len(detail)) }
    if !strings.Contains(detail, "open interface take too much time") { t.Fatal("warning absent") }
}
```

- [ ] **Step 2: Verify RED**

Run:

```powershell
$env:GOOS='windows'; go test ./internal/supervisor -run TestReadyTimeoutReturnsBoundedRedactedCoreTail -count=1
```

Expected: FAIL because logs are discarded and no diagnostic tail API exists.

- [ ] **Step 3: Implement an in-memory bounded sink**

Attach a concurrency-safe tail buffer as the supervisor log destination, pass it through the existing redactor, and expose only a sanitized bounded copy. In `supervisedProcessInstance.Ready`, wrap readiness timeout with a staged diagnostic whose public detail is the tail. Do not write raw core output to disk or trace.

- [ ] **Step 4: Verify GREEN**

Run:

```powershell
$env:GOOS='windows'; go test ./internal/supervisor ./cmd/overseas-agent -count=1
```

Expected: PASS.

- [ ] **Step 5: Commit**

```powershell
git add internal/supervisor/process_windows.go internal/supervisor/process_windows_test.go cmd/overseas-agent/main_windows.go cmd/overseas-agent/main_windows_test.go
git commit -m "fix(supervisor): retain safe readiness diagnostics"
```

---

### Task 4: Prove MSI Upgrade Identity and Transactional Trust

**Files:**
- Modify: `deploy/client/Product.wxs`
- Modify: `deploy/client/install-client.ps1`
- Modify: `scripts/windows/build-client-artifacts.ps1`
- Modify: `scripts/windows/inspect-client-msi.ps1`
- Modify: `scripts/windows/publish-client-release.ps1`
- Test: `tests/powershell/ClientInstall.Tests.ps1`

**Interfaces:**
- Consumes: stable UpgradeCode `A4D8477C-7F2D-46E6-9B5C-65BE7E8474E1`, transactional `TelecomMitmRootTrust`, artifact manifest, and clean-worktree release gate.
- Produces: one version constant consumed by WiX, installer script, manifest builder, output filename, and inspector assertions.

- [ ] **Step 1: Write failing release-identity tests**

Replace the three independent `0.1.6` text assertions with a single release-version source test. Require the release filename, MSI ProductVersion, install script version, and manifest version to derive from it. Add an inspector assertion for Upgrade table rows using the stable UpgradeCode and a post-install verification script that fails unless exactly one matching registration exists.

```powershell
It 'derives every release identity from one version and verifies one registration' {
    $publisher | Should Match 'ReleaseVersion'
    $publisher | Should Match 'OverseasAccessSetup-v\$ReleaseVersion-poc-RELEASE_SIGNED\.msi'
    $inspector | Should Match 'A4D8477C-7F2D-46E6-9B5C-65BE7E8474E1'
    $inspector | Should Match 'matchingRegistrations\.Count\s*-ne\s*1'
}
```

- [ ] **Step 2: Verify RED**

Run:

```powershell
Invoke-Pester tests/powershell/ClientInstall.Tests.ps1 -TestName '*release identity*','*one registration*'
```

Expected: FAIL because version strings and output identity are independently maintained and installed-registration verification is absent.

- [ ] **Step 3: Implement one release version input and upgrade inspection**

Introduce a mandatory validated `ReleaseVersion` at publication, pass it to WiX as `-d ProductVersion=...` and the payload builder, and render the install script version in the staged payload without modifying the source template. Update `Product.wxs` to use `$(var.ProductVersion)` while preserving the stable UpgradeCode and `MajorUpgrade`. Extend inspection to reject missing/duplicate Upgrade table coverage and mismatched manifest/MSI version.

- [ ] **Step 4: Add field post-install verifier**

Add a read-only verification mode to the existing release inspection tooling that checks:

```powershell
$registrations = @(Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* |
  Where-Object DisplayName -eq 'RegenBio Overseas Access')
if ($registrations.Count -ne 1) { throw "Expected one product registration; found $($registrations.Count)." }
if ($registrations[0].DisplayVersion -ne $ExpectedVersion) { throw 'Installed version mismatch.' }
if (-not (Get-ChildItem Cert:\LocalMachine\Root | Where-Object Thumbprint -eq $ExpectedRootThumbprint)) {
  throw 'Telecom MITM root is absent.'
}
```

- [ ] **Step 5: Verify GREEN and the full Pester suite**

Run:

```powershell
Invoke-Pester tests/powershell/ClientInstall.Tests.ps1
Invoke-Pester tests/powershell
```

Expected: all tests PASS.

- [ ] **Step 6: Commit**

```powershell
git add deploy/client/Product.wxs deploy/client/install-client.ps1 scripts/windows/build-client-artifacts.ps1 scripts/windows/inspect-client-msi.ps1 scripts/windows/publish-client-release.ps1 tests/powershell/ClientInstall.Tests.ps1
git commit -m "fix(installer): enforce authoritative client upgrade"
```

---

### Task 5: Build, Sign, Deploy, and Field-Verify the PoC

**Files:**
- Generated: `dist/OverseasAccessSetup-v0.1.7-poc-RELEASE_SIGNED.msi`
- Create: `outputs/windows-client-field-validation-20260904/REPORT.md`

**Interfaces:**
- Consumes: the corporate signing certificate, locked release toolchain, SSH debug access to `172.20.20.200`, and the existing client named-pipe protocol.
- Produces: signed MSI, SHA-256 digest, endpoint evidence, and final Git commit containing the validation report but not generated binaries.

- [ ] **Step 1: Run all automated verification from a clean tree**

Run:

```powershell
go test ./...
$env:GOOS='windows'; go test ./...
Invoke-Pester tests/powershell
git diff --check
git status --short
```

Expected: all tests PASS and the worktree is clean before publication.

- [ ] **Step 2: Publish and verify the signed MSI**

Run `scripts/windows/publish-client-release.ps1` with release version `0.1.7` and the current corporate signing thumbprint. Record:

```powershell
Get-FileHash $msi -Algorithm SHA256
Get-AuthenticodeSignature $msi | Format-List Status,SignerCertificate
```

Expected: `Status = Valid`, manifest version equals MSI version, and filename contains the same version.

- [ ] **Step 3: Remove temporary test-only SSH diagnostics before deployment**

On `172.20.20.200`, unregister `RegenBio-System-Core-Diagnostic`, stop only the non-service debug sshd on port 2222 after normal port-22 key authentication has been proven, and remove only the temporary firewall rule `RegenBio-OpenSSH-Debug`. Do not disable password authentication until port-22 key login succeeds.

- [ ] **Step 4: Upgrade using the verified digest**

Copy the exact MSI by SCP, recompute its SHA-256 remotely, compare it byte-for-byte to the local digest, then run an elevated silent MSI upgrade with verbose logging. Abort if the digest differs. Run the post-install verifier and require one registration, expected version/commit, valid service paths, and the expected Go MITM root.

- [ ] **Step 5: Verify connection, TLS, and self-recovery**

Use the named-pipe client request to connect and require:

```powershell
curl.exe -sS -I --max-time 15 https://www.google.com/
curl.exe -sS -I --max-time 15 https://www.youtube.com/
```

Expected: exit code 0 without `-k`. Disconnect, verify zero residue, reconnect, and repeat both requests. Create one product-owned phantom in a controlled test only if the normal failed-start path does not naturally reproduce it; verify the next connection removes only that exact instance.

- [ ] **Step 6: Verify two monitor intervals**

Keep active traffic flowing for at least ten minutes. Query status and trace immediately before and after minutes five and ten. Expected: state remains `connected`; no zero-rule `firewall_audit` or `emergency` event appears; Google and YouTube continue returning successful HTTPS responses.

- [ ] **Step 7: Disconnect and prove zero residue**

Require zero product TUNs, routes, sing-box processes, active managed firewall rules, and runtime snapshot. Confirm ordinary direct networking remains functional.

- [ ] **Step 8: Write and commit the validation report**

Record MSI path, SHA-256, Authenticode signer, installed version/commit, certificate thumbprint, timing, TLS results, ten-minute status checks, residue result, and any remaining limitations in `outputs/windows-client-field-validation-20260904/REPORT.md`.

```powershell
git add outputs/windows-client-field-validation-20260904/REPORT.md
git commit -m "docs: record Windows client field validation"
```
