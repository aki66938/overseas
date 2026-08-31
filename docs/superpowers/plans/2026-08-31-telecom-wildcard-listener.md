# Telecom Wildcard Listener Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Permit the observed wildcard TCP 8080 telecom CONNECT listener while removing product ownership of the TCP 8080 firewall block.

**Architecture:** Keep `Get-TelecomConnectEvidence` as the fail-closed identity, signature, hash and CONNECT gate, but broaden its accepted listener-address set. Reduce the server transaction's canonical firewall ownership set from three rules to the employee TCP 18443 allow and employee management protection rules.

**Tech Stack:** Windows PowerShell 5.1, Pester 3.4-compatible tests, Windows Firewall cmdlets, sing-box 1.13.19.

## Global Constraints

- Accepted TCP 8080 listener addresses are exactly `127.0.0.1`, `::1`, `0.0.0.0`, and `::`.
- TCP 8080 must still have exactly one listener, a live owning process with a concrete path, a valid Authenticode signature, and a successful HTTPS CONNECT probe.
- The product must neither create nor require `RegenBioOverseasAccess-Block8080-Remote`.
- The product owns exactly `RegenBioOverseasAccess-AllowEmployee-In` and `RegenBioOverseasAccess-BlockManagement-Employee`.
- No test or implementation step may mutate the live VM; live deployment occurs only after unit verification and `-WhatIf`.

---

### Task 1: Broaden telecom evidence and reduce firewall ownership

**Files:**
- Modify: `tests/powershell/ServerInstall.Tests.ps1`
- Modify: `deploy/server/install-server.ps1`
- Modify: `.superpowers/sdd/task-7-report.md`

**Interfaces:**
- Consumes: `Get-TelecomConnectEvidence`, `$FirewallNames`, transaction `FirewallRules`, `Remove-OwnedFirewallRule`.
- Produces: a two-rule canonical ownership set and wildcard-compatible telecom preflight evidence.

- [ ] **Step 1: Write failing listener compatibility tests**

Replace the old `Owner8080` negative case with table-driven behavioral cases that invoke the real installer preflight under mocks. Make `[::]` and `0.0.0.0` return a valid single listener and expect the preflight to proceed past the old `loopback-only` failure. Retain negative cases for two listeners, PID zero, missing process path, invalid Authenticode status, and failed `Invoke-WebRequest`.

```powershell
foreach ($address in @('::', '0.0.0.0')) {
    It "accepts the approved wildcard telecom listener $address" {
        $global:Task7TelecomAddress = $address
        { & $scriptPath @validWhatIfParameters -WhatIf } |
            Should Not Throw 'TCP 8080 must be loopback-only'
    }
}
```

- [ ] **Step 2: Write failing firewall ownership tests**

Assert the source no longer contains the fixed TCP 8080 rule name or its `New-NetFirewallRule` block, and behaviorally assert install/rollback/status use exactly the two remaining names.

```powershell
$text | Should Not Match 'RegenBioOverseasAccess-Block8080-Remote'
$text | Should Not Match 'keep telecom proxy local only'
@($expectedTransaction.FirewallRules).Count | Should Be 2
```

- [ ] **Step 3: Run RED tests**

Run:

```powershell
powershell.exe -NoProfile -Command "$r=Invoke-Pester -Script tests/powershell/ServerInstall.Tests.ps1 -PassThru; if($r.FailedCount -eq 0){exit 2}else{exit 0}"
pwsh -NoProfile -Command "$r=Invoke-Pester -Script tests/powershell/ServerInstall.Tests.ps1 -PassThru; if($r.FailedCount -eq 0){exit 2}else{exit 0}"
```

Expected: both commands witness failures caused by the loopback-only guard and the existing third firewall rule.

- [ ] **Step 4: Implement the minimal listener change**

In `Get-TelecomConnectEvidence`, replace the loopback-only predicate with the exact accepted set while leaving listener count, PID, live process, path, hash, signature and CONNECT checks intact:

```powershell
$acceptedTelecomAddresses = @('127.0.0.1', '::1', '0.0.0.0', '::')
if ([string] $listener.LocalAddress -notin $acceptedTelecomAddresses) {
    throw "TCP $TelecomProxyPort listener address is unsupported: $($listener.LocalAddress)."
}
```

- [ ] **Step 5: Implement the minimal firewall ownership change**

Delete `$FirewallBlock8080`, remove it from `$FirewallNames`, remove its creation block, and remove it from compensation and rollback order. Preserve the dependency-safe order for the two remaining rules:

```powershell
$FirewallNames = @($FirewallAllowEmployee, $FirewallBlockManagement)

foreach ($firewallName in @($FirewallBlockManagement, $FirewallAllowEmployee)) {
    Remove-OwnedFirewallRule -Name $firewallName -TransactionId $transactionId
}
```

- [ ] **Step 6: Run focused GREEN tests**

Run:

```powershell
powershell.exe -NoProfile -Command "$r=Invoke-Pester -Script tests/powershell/ServerInstall.Tests.ps1 -PassThru; if($r.FailedCount -ne 0){exit 1}"
pwsh -NoProfile -Command "$r=Invoke-Pester -Script tests/powershell/ServerInstall.Tests.ps1 -PassThru; if($r.FailedCount -ne 0){exit 1}"
```

Expected: all `ServerInstall.Tests.ps1` cases pass in both engines.

- [ ] **Step 7: Run full regression gates**

Run:

```powershell
& 'C:\Users\Eleme\codex_workspace\.tools\go1.27.0\go\bin\go.exe' test -count=1 ./...
& 'C:\Users\Eleme\codex_workspace\.tools\go1.27.0\go\bin\go.exe' vet ./...
powershell.exe -NoProfile -Command "$r=Invoke-Pester -Script tests/powershell -PassThru; if($r.FailedCount -ne 0){exit 1}"
pwsh -NoProfile -Command "$r=Invoke-Pester -Script tests/powershell -PassThru; if($r.FailedCount -ne 0){exit 1}"
git diff --check
```

Expected: Go test/vet exit 0, both full Pester suites have zero failures, and diff check is clean.

- [ ] **Step 8: Update evidence and commit**

Append the exact RED/GREEN commands and accepted PoC exposure risk to `.superpowers/sdd/task-7-report.md`, then commit only the planned files:

```powershell
git add deploy/server/install-server.ps1 tests/powershell/ServerInstall.Tests.ps1 .superpowers/sdd/task-7-report.md
git commit -m "fix: accept telecom wildcard CONNECT listener"
```

Expected: commit succeeds and `git status --short` is empty.

### Task 2: Live WhatIf and bounded deployment

**Files:**
- No source changes.
- Create on VM101: `C:\Staging\OverseasAccessServer\` artifacts and evidence only after hash verification.

**Interfaces:**
- Consumes: signed first-party service host, pinned sing-box 1.13.19, rendered server config, exact SHA-256 values, `install-server.ps1`.
- Produces: a validated `-WhatIf` evidence record, followed only on success by the owned server service and TCP 18443 listener.

- [ ] **Step 1: Build and sign the server bundle locally**

Build `overseas-server-service.exe` with locked Go 1.27.0, sign it with PoC thumbprint `6A9D8BC41086C6B764B8C7439E797671EF83C15E`, and create a runtime manifest containing exact sing-box and service hashes. Verify all hashes and Authenticode before transfer.

- [ ] **Step 2: Render one matched server/client credential contract**

Generate a random Shadowsocks 2022 secret without command-line or log disclosure. Render the server configuration with HTTP outbound `127.0.0.1:8080`; preserve the same secret only in the protected client provisioning contract.

- [ ] **Step 3: Transfer and rehash on VM101**

Use the pinned VM101 Ed25519 host key and strict SSH options. Copy to a new staging directory, then rehash every artifact remotely and refuse any mismatch.

- [ ] **Step 4: Execute server `-WhatIf`**

Run the complete installer with `-WhatIf` and an empty absolute evidence path. Expected: telecom `[::]:8080` evidence passes, no mutation occurs, and the output describes exactly two product firewall rules.

- [ ] **Step 5: Install only after WhatIf success**

Run the identical command without `-WhatIf`. Verify service Running, TCP 18443 owned by the installed core, the employee-CIDR allow rule, management protection, and continued telecom CONNECT success.

- [ ] **Step 6: Stop on any failed proof**

If staging, rehash, WhatIf, install, readiness or CONNECT verification fails, do not proceed to client TUN installation. Use the installer's exact rollback mode only for product-owned resources and preserve evidence for diagnosis.
