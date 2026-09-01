# v15 PowerShell Transport and DNS Prefix Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build, sign, and install a v15 Windows client that preserves Unicode adapter identities across the Go/Windows PowerShell 5.1 boundary and publishes an equivalent Windows-compatible DNS IPv6 block set.

**Architecture:** The Go runner wraps every UTF-8 JSON request in an ASCII Base64 stdin envelope and prepends one shared PowerShell transport prologue that performs strict UTF-8 decoding, forces UTF-8 stdout, and suppresses Progress. The Windows policy generator normalizes only `::/0` into `::/1` plus `8000::/1`; the existing manager then uses that one normalized collection for capture, ordinary publication, emergency publication, ActiveStore verification, and restore.

**Tech Stack:** Go 1.27.0, Windows PowerShell 5.1, PowerShell 7, Pester 3.4.0, Windows NetSecurity cmdlets, WiX 6.0.2, Authenticode/SignTool.

## Global Constraints

- Keep the existing sing-box TUN and HTTP CONNECT node `172.20.9.15:8080` unchanged.
- Do not modify, stop, or configure FlClash; only the user closes it for final acceptance.
- Preserve fail-closed behavior and exact ownership of `RegenBioOverseasAccess.Managed`, metrics `4096/8192`, the fixed TUN alias, and `network-state.json`.
- Base64 input has no raw-JSON compatibility fallback.
- Reject malformed Base64, invalid UTF-8, malformed JSON, and invalid UTF-8 stdout before consuming data or mutating network state.
- Replace exact `::/0` only with `::/1` and `8000::/1`; retain all other prefix strings and first-seen order, and remove duplicates.
- Diagnostics remain stage-bounded, control-character-free, at most 512 UTF-8 bytes, and contain no request envelope, policy, configuration, or credential.
- Every live gate ends with zero product firewall rules, zero diagnostic rules, zero product routes, zero product TUN, and no `network-state.json`.
- End-to-end success is not claimed until the user closes FlClash, reaches `connected`, verifies overseas and corporate access, disconnects, and confirms clean recovery.

## File Structure

- Modify `internal/agent/network_windows.go`: define the shared transport prologue, Base64 envelope helper, strict stdout validation, and Windows firewall prefix normalization.
- Modify `internal/agent/network_windows_test.go`: add unit and process-level regression tests for Unicode transport, malformed output, Progress suppression, and DNS normalization.
- Create `internal/agent/network_windows_integration_test.go`: add the opt-in LocalSystem live capture/block/verify/restore transaction.
- Create `scripts/windows/verify-client-network-transaction.ps1`: run the opt-in Go transaction under LocalSystem and publish bounded evidence.
- Create `tests/powershell/ClientNetworkTransaction.Tests.ps1`: enforce the live-gate script's identity, path, evidence, and cleanup contract without mutating networking.
- Create `docs/superpowers/specs/2026-09-01-v15-powershell-transport-and-dns-prefix-design.md`: already committed design source of truth.

---

### Task 1: Locale-Independent PowerShell Transport

**Files:**
- Modify: `internal/agent/network_windows.go:976-1006,1154-1400`
- Test: `internal/agent/network_windows_test.go`

**Interfaces:**
- Consumes: UTF-8 JSON `[]byte` passed to `networkRunner.Run`.
- Produces: `func powerShellInputEnvelope([]byte) []byte`, `const networkPowerShellTransportPrologue string`, and strict UTF-8 stdout from `powerShellNetworkRunner.Run`.

- [ ] **Step 1: Write failing unit and real-process tests**

Add tests with these exact assertions:

```go
func TestPowerShellInputEnvelopeIsASCIIAndRoundTripsUnicodeJSON(t *testing.T) {
	input := []byte(`{"InterfaceAlias":"以太网","Secondary":"本地连接"}`)
	envelope := powerShellInputEnvelope(input)
	for _, value := range envelope {
		if value > 0x7f { t.Fatalf("envelope contains non-ASCII byte %x", value) }
	}
	decoded, err := base64.StdEncoding.DecodeString(string(envelope))
	if err != nil || !bytes.Equal(decoded, input) {
		t.Fatalf("round trip = %q, %v", decoded, err)
	}
}

func TestPowerShellNetworkRunnerRoundTripsUnicodeUnderSystemCodePage(t *testing.T) {
	const operation = "transport_unicode_test"
	networkPowerShellScripts[operation] = `[pscustomobject]@{InterfaceAlias=[string]$i.InterfaceAlias;Secondary=[string]$i.Secondary}|ConvertTo-Json -Compress`
	defer delete(networkPowerShellScripts, operation)
	input := []byte(`{"InterfaceAlias":"以太网","Secondary":"本地连接"}`)
	output, err := (powerShellNetworkRunner{}).Run(context.Background(), operation, input)
	if err != nil { t.Fatal(err) }
	if !utf8.Valid(output) { t.Fatalf("stdout is not UTF-8: %x", output) }
	var got map[string]string
	if err := json.Unmarshal(output, &got); err != nil { t.Fatal(err) }
	if got["InterfaceAlias"] != "以太网" || got["Secondary"] != "本地连接" { t.Fatalf("round trip = %#v", got) }
}

func TestPowerShellNetworkRunnerRejectsInvalidUTF8Stdout(t *testing.T) {
	const operation = "transport_invalid_stdout_test"
	networkPowerShellScripts[operation] = `$stream=[Console]::OpenStandardOutput();$stream.WriteByte(255);$stream.Flush()`
	defer delete(networkPowerShellScripts, operation)
	if _, err := (powerShellNetworkRunner{}).Run(context.Background(), operation, []byte(`{}`)); err == nil || !strings.Contains(err.Error(), "invalid PowerShell UTF-8 output") {
		t.Fatalf("invalid stdout error = %v", err)
	}
}

func TestPowerShellNetworkRunnerRejectsInvalidUTF8InputBeforeScriptBody(t *testing.T) {
	const operation = "transport_invalid_input_test"
	networkPowerShellScripts[operation] = `Write-Output 'script_body_reached'`
	defer delete(networkPowerShellScripts, operation)
	if output, err := (powerShellNetworkRunner{}).Run(context.Background(), operation, []byte{0xff}); err == nil || bytes.Contains(output, []byte("script_body_reached")) {
		t.Fatalf("invalid input reached body: output=%q err=%v", output, err)
	}
}

func TestPowerShellTransportSuppressesProgressBeforeFailure(t *testing.T) {
	const operation = networkOperationBlock
	original := networkPowerShellScripts[operation]
	networkPowerShellScripts[operation] = `Write-Progress -Activity noisy -Completed;throw 'transport_marker'`
	defer func(){ networkPowerShellScripts[operation] = original }()
	_, err := (powerShellNetworkRunner{}).Run(context.Background(), operation, []byte(`{}`))
	diagnostic, ok := err.(interface{ DiagnosticDetail() string })
	if !ok || !strings.Contains(diagnostic.DiagnosticDetail(), "transport_marker") || strings.Contains(diagnostic.DiagnosticDetail(), "S=\"progress\"") {
		t.Fatalf("diagnostic = %#v", err)
	}
}
```

Add `bytes` and `encoding/base64` to the test imports; the production file already imports the required Base64 and UTF-8 packages.

- [ ] **Step 2: Run the focused tests and verify RED**

Run:

```powershell
& 'C:\Users\Eleme\codex_workspace\.tools\go1.27.0\go\bin\go.exe' test ./internal/agent -run 'PowerShellInputEnvelope|PowerShellNetworkRunner|PowerShellTransportSuppresses' -count=1 -v
```

Expected: compile failure for missing `powerShellInputEnvelope`, followed by behavior failures until the transport prologue and strict stdout validation exist.

- [ ] **Step 3: Implement the Base64 envelope and shared prologue**

Add the following production boundary and compose it with every operation script:

```go
func powerShellInputEnvelope(input []byte) []byte {
	return []byte(base64.StdEncoding.EncodeToString(input))
}

const networkPowerShellTransportPrologue = `$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$utf8 = New-Object System.Text.UTF8Encoding($false, $true)
[Console]::OutputEncoding = $utf8
$OutputEncoding = $utf8
$envelope = [Console]::In.ReadToEnd().Trim()
if ([string]::IsNullOrWhiteSpace($envelope)) { throw 'PowerShell input envelope is empty.' }
$jsonBytes = [Convert]::FromBase64String($envelope)
$json = $utf8.GetString($jsonBytes)
$i = ($json | ConvertFrom-Json)`

func (powerShellNetworkRunner) Run(ctx context.Context, operation string, input []byte) ([]byte, error) {
	script, exists := networkPowerShellScripts[operation]
	if !exists { return nil, errors.New("unknown network operation") }
	command := exec.CommandContext(ctx, "powershell.exe", "-NoProfile", "-NonInteractive", "-EncodedCommand", encodePowerShell(networkPowerShellTransportPrologue+"\n"+script))
	command.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	command.Stdin = bytes.NewReader(powerShellInputEnvelope(input))
	var stdout, stderr bytes.Buffer
	command.Stdout, command.Stderr = &stdout, &stderr
	if err := command.Start(); err != nil { return nil, newFixedNetworkOperationError(operation, err, nil) }
	if err := command.Wait(); err != nil { return nil, newFixedNetworkOperationError(operation, err, stderr.Bytes()) }
	if !utf8.Valid(stdout.Bytes()) {
		const detail = "invalid PowerShell UTF-8 output"
		return nil, newFixedNetworkOperationError(operation, errors.New(detail), []byte(detail))
	}
	return bytes.TrimSpace(stdout.Bytes()), nil
}
```

Remove the duplicated `$ErrorActionPreference` and raw `[Console]::In.ReadToEnd() | ConvertFrom-Json` lines from all eight operation bodies. The shared prologue must be the only stdin decoder.

- [ ] **Step 4: Run focused and package tests and verify GREEN**

Run:

```powershell
& 'C:\Users\Eleme\codex_workspace\.tools\go1.27.0\go\bin\go.exe' test ./internal/agent -run 'PowerShellInputEnvelope|PowerShellNetworkRunner|PowerShellTransportSuppresses|WindowsNetwork' -count=1
```

Expected: PASS; the Unicode process test returns the exact Chinese aliases and the diagnostic contains `transport_marker` without a Progress object.

- [ ] **Step 5: Commit the transport slice**

```powershell
git add internal/agent/network_windows.go internal/agent/network_windows_test.go
git commit -m "fix(windows): make PowerShell transport locale independent"
```

---

### Task 2: Windows-Compatible DNS IPv6 Prefixes

**Files:**
- Modify: `internal/agent/network_windows.go:270-289,1083-1110`
- Test: `internal/agent/network_windows_test.go:629-641`

**Interfaces:**
- Consumes: ordered firewall prefix strings.
- Produces: `func normalizeWindowsFirewallPrefixes([]string) []string`; `WindowsNetworkManager.dnsBlockedPrefixes` never contains `::/0`.

- [ ] **Step 1: Write failing normalization and manager tests**

```go
func TestNormalizeWindowsFirewallPrefixesSplitsIPv6DefaultAndDeduplicates(t *testing.T) {
	input := []string{"10.0.0.0/8", "::/0", "::/1", "192.0.2.1/32", "::/0"}
	want := []string{"10.0.0.0/8", "::/1", "8000::/1", "192.0.2.1/32"}
	if got := normalizeWindowsFirewallPrefixes(input); !slices.Equal(got, want) { t.Fatalf("normalized = %#v, want %#v", got, want) }
}

func TestWindowsNetworkDNSFirewallPrefixesExcludeRejectedIPv6Default(t *testing.T) {
	manager, err := newWindowsNetworkManager(validPolicy(), `C:\state.json`, &fakeNetworkRunner{}, &fakeSnapshotStore{})
	if err != nil { t.Fatal(err) }
	if slices.Contains(manager.dnsBlockedPrefixes, "::/0") || !slices.Contains(manager.dnsBlockedPrefixes, "::/1") || !slices.Contains(manager.dnsBlockedPrefixes, "8000::/1") {
		t.Fatalf("DNS firewall prefixes = %#v", manager.dnsBlockedPrefixes)
	}
	assertAddressCovered(t, manager.dnsBlockedPrefixes, netip.MustParseAddr("2001:4860:4860::8888"), true)
	assertAddressCovered(t, manager.dnsBlockedPrefixes, netip.MustParseAddr("fd00::53"), true)
}
```

Add `slices` to the test imports.

- [ ] **Step 2: Run focused tests and verify RED**

Run:

```powershell
& 'C:\Users\Eleme\codex_workspace\.tools\go1.27.0\go\bin\go.exe' test ./internal/agent -run 'NormalizeWindowsFirewallPrefixes|DNSFirewallPrefixes' -count=1 -v
```

Expected: compile failure because `normalizeWindowsFirewallPrefixes` does not exist, or assertion failure because `::/0` remains.

- [ ] **Step 3: Implement exact prefix normalization at policy construction**

```go
func normalizeWindowsFirewallPrefixes(values []string) []string {
	result := make([]string, 0, len(values)+1)
	seen := make(map[string]struct{}, len(values)+1)
	appendUnique := func(value string) {
		if _, exists := seen[value]; exists { return }
		seen[value] = struct{}{}
		result = append(result, value)
	}
	for _, value := range values {
		if value == "::/0" {
			appendUnique("::/1")
			appendUnique("8000::/1")
			continue
		}
		appendUnique(value)
	}
	return result
}
```

Change the DNS construction to:

```go
dnsBlocked := normalizeWindowsFirewallPrefixes(append(
	complementIPv4Prefixes(dnsExcluded4),
	complementIPv6From(netip.MustParsePrefix("::/0"), nil)...,
))
```

- [ ] **Step 4: Verify normal, emergency, snapshot, verify, and restore inputs share the normalized set**

Extend the fake-runner test to compare `DNSBlockedRemoteAddresses` from `capture`, `block`, `verify`, `emergency`, and `restore` with `manager.dnsBlockedPrefixes`, then run:

```powershell
& 'C:\Users\Eleme\codex_workspace\.tools\go1.27.0\go\bin\go.exe' test ./internal/agent -run 'DNS|Emergency|Restore' -count=1
```

Expected: PASS and no captured input contains `::/0`.

- [ ] **Step 5: Commit the DNS slice**

```powershell
git add internal/agent/network_windows.go internal/agent/network_windows_test.go
git commit -m "fix(windows): normalize IPv6 DNS firewall prefixes"
```

---

### Task 3: LocalSystem End-to-End Network Transaction Gate

**Files:**
- Create: `internal/agent/network_windows_integration_test.go`
- Create: `scripts/windows/verify-client-network-transaction.ps1`
- Create: `tests/powershell/ClientNetworkTransaction.Tests.ps1`

**Interfaces:**
- Consumes: `OVERSEAS_ACCESS_NETWORK_GATE=1`, LocalSystem SID `S-1-5-18`, locked Go executable, clean product network state.
- Produces: a create-new JSON evidence file containing identity, exit code, bounded test output, and post-run residue counts.

- [ ] **Step 1: Write failing Pester contract tests before creating the gate script**

Assert that the missing script must contain all of these literals and behaviors:

```powershell
Describe 'Client LocalSystem network transaction gate' {
    $path = Join-Path $PSScriptRoot '..\..\scripts\windows\verify-client-network-transaction.ps1'
    It 'requires LocalSystem and explicit clean absolute inputs' {
        $text = Get-Content -LiteralPath $path -Raw
        $text | Should Match ([regex]::Escape("S-1-5-18"))
        $text | Should Match ([regex]::Escape("OVERSEAS_ACCESS_NETWORK_GATE"))
        $text | Should Match ([regex]::Escape("network-state.json"))
        $text | Should Match ([regex]::Escape("RegenBioOverseasAccess.Managed"))
        $text | Should Match ([regex]::Escape("RegenBio.Diagnostic"))
        $text | Should Match ([regex]::Escape("RouteMetric -in 4096,8192"))
        $text | Should Match ([regex]::Escape("[IO.FileMode]::CreateNew"))
    }
}
```

- [ ] **Step 2: Run Pester and verify RED**

Run:

```powershell
$r = Invoke-Pester -Script tests/powershell/ClientNetworkTransaction.Tests.ps1 -PassThru -Quiet
if ($r.FailedCount -eq 0) { throw 'Expected RED before gate script exists.' }
```

Expected: FAIL because the gate script does not exist.

- [ ] **Step 3: Add the opt-in Go live transaction test**

Create a Windows-only test that skips unless the environment flag is exact and the current token is LocalSystem:

```go
//go:build windows

package agent

func TestLiveWindowsPowerShellProtectionTransaction(t *testing.T) {
	if os.Getenv("OVERSEAS_ACCESS_NETWORK_GATE") != "1" { t.Skip("live gate disabled") }
	token := windows.GetCurrentProcessToken()
	user, err := token.GetTokenUser()
	if err != nil || user.User.Sid.String() != "S-1-5-18" { t.Fatalf("gate is not LocalSystem: %v, %v", user, err) }
	statePath := filepath.Join(t.TempDir(), "network-state.json")
	manager, err := newWindowsNetworkManager(validPolicy(), statePath, powerShellNetworkRunner{}, fileSnapshotStore{})
	if err != nil { t.Fatal(err) }
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	snapshot, err := manager.Capture(ctx)
	if err != nil { t.Fatal(err) }
	restored := false
	defer func() {
		if !restored {
			if restoreErr := manager.Restore(context.Background(), snapshot); restoreErr != nil { t.Errorf("cleanup restore: %v", restoreErr) }
		}
	}()
	if _, err := manager.InstallPublicTCPBlock(ctx); err != nil { t.Fatal(err) }
	if err := manager.Restore(ctx, snapshot); err != nil { t.Fatal(err) }
	restored = true
	if _, err := os.Stat(statePath); !errors.Is(err, os.ErrNotExist) { t.Fatalf("state residue: %v", err) }
}
```

Include the required imports: `context`, `errors`, `os`, `path/filepath`, `testing`, `time`, and `golang.org/x/sys/windows`.

- [ ] **Step 4: Implement the PowerShell evidence wrapper**

The script must validate absolute `RepositoryPath`, `GoExecutable`, and create-new `EvidencePath`; require elevation and SID `S-1-5-18`; refuse preexisting rules/routes/TUN/snapshot; run only:

```powershell
$env:OVERSEAS_ACCESS_NETWORK_GATE = '1'
$output = & $GoExecutable test ./internal/agent -run '^TestLiveWindowsPowerShellProtectionTransaction$' -count=1 -v 2>&1 | Out-String
$exitCode = $LASTEXITCODE
```

In `finally`, query exact residue, cap normalized output at 4096 characters, write evidence using `IO.FileStream` with `FileMode.CreateNew`, and exit nonzero unless the Go exit code and all residue counts are zero.

- [ ] **Step 5: Run focused Go/Pester tests and verify GREEN**

Run under ordinary administration first; the Go live test must skip and Pester must pass:

```powershell
& 'C:\Users\Eleme\codex_workspace\.tools\go1.27.0\go\bin\go.exe' test ./internal/agent -run '^TestLiveWindowsPowerShellProtectionTransaction$' -count=1 -v
$r = Invoke-Pester -Script tests/powershell/ClientNetworkTransaction.Tests.ps1 -PassThru -Quiet
if ($r.FailedCount -gt 0) { exit 1 }
```

Expected: Go `SKIP`, Pester all PASS.

- [ ] **Step 6: Run the gate as LocalSystem and verify exact cleanup**

Register one temporary scheduled task with `UserId SYSTEM`, `LogonType ServiceAccount`, and `RunLevel Highest` to invoke `verify-client-network-transaction.ps1` with the locked Go path, repository path, and a new evidence path under `C:\ProgramData\RegenBio`. Start it once, wait at most 60 seconds, inspect `Success=true`, `SID=S-1-5-18`, Go exit `0`, and all residue fields `0/false`; then unregister only that exact task and delete only its exact evidence file.

Expected: full real capture, Base64/UTF-8 transport, adapter rule publication, ActiveStore verification, DNS publication, restore, and zero residue all pass under LocalSystem.

- [ ] **Step 7: Commit the live gate**

```powershell
git add internal/agent/network_windows_integration_test.go scripts/windows/verify-client-network-transaction.ps1 tests/powershell/ClientNetworkTransaction.Tests.ps1
git commit -m "test(windows): gate the full LocalSystem network transaction"
```

---

### Task 4: Full Verification and Signed v15 Publication

**Files:**
- Verify: all Go and PowerShell source
- Create ignored artifact: `dist/OverseasAccessSetup-POC-DIRECT-HTTP-v15-RELEASE_SIGNED.msi`

**Interfaces:**
- Consumes: clean Git HEAD, locked Go/WiX dependencies, SignTool, PoC signing certificate thumbprint `6A9D8BC41086C6B764B8C7439E797671EF83C15E`.
- Produces: signed v15 MSI bound to the exact source commit and a zero-failure verification record.

- [ ] **Step 1: Run formatting, diff, Go tests, and vet**

```powershell
& 'C:\Users\Eleme\codex_workspace\.tools\go1.27.0\go\bin\gofmt.exe' -w internal/agent/network_windows.go internal/agent/network_windows_test.go internal/agent/network_windows_integration_test.go
git diff --check
& 'C:\Users\Eleme\codex_workspace\.tools\go1.27.0\go\bin\go.exe' test ./... -count=1
& 'C:\Users\Eleme\codex_workspace\.tools\go1.27.0\go\bin\go.exe' vet ./...
```

Expected: no diff errors, every Go package PASS, vet exit `0`.

- [ ] **Step 2: Run all Pester tests in both runtimes and AST-parse every script**

```powershell
$r = Invoke-Pester -Script tests/powershell -PassThru -Quiet
if ($r.FailedCount -gt 0) { exit 1 }
powershell.exe -NoProfile -Command "& { Import-Module Pester; `$r=Invoke-Pester -Script 'tests/powershell' -PassThru -Quiet; if (`$r.FailedCount -gt 0) { exit 1 } }"
```

Then parse every repository `*.ps1` with `System.Management.Automation.Language.Parser.ParseFile`; expected zero parse errors.

- [ ] **Step 3: Re-run the LocalSystem live transaction immediately before publication**

Use Task 3 Step 6 exactly. Expected: `Success=true`, eight currently registered IP-stack adapters or the exact current discovered count all verified by the transaction, and zero residue afterward.

- [ ] **Step 4: Commit any final test-only corrections and require a clean tree**

```powershell
git status --short
git log -4 --oneline
```

Expected: empty status. Do not publish from a dirty tree.

- [ ] **Step 5: Build and sign v15**

```powershell
& .\scripts\windows\publish-client-release.ps1 `
  -SigningCertificateThumbprint '6A9D8BC41086C6B764B8C7439E797671EF83C15E' `
  -SignToolPath 'C:\Program Files (x86)\Windows Kits\10\bin\10.0.26100.0\x64\signtool.exe' `
  -FinalMsiPath 'dist/OverseasAccessSetup-POC-DIRECT-HTTP-v15-RELEASE_SIGNED.msi'
```

Expected: exit `0`; MSI Authenticode status `Valid`; embedded manifest mode `release`, source commit equals `git rev-parse HEAD`, and all installed-required binary signer thumbprints match the manifest.

---

### Task 5: Controlled v14-to-v15 Upgrade and User Acceptance Handoff

**Files:**
- Install: `dist/OverseasAccessSetup-POC-DIRECT-HTTP-v15-RELEASE_SIGNED.msi`
- Evidence: exact `%TEMP%` MSI uninstall/install logs

**Interfaces:**
- Consumes: sole v14 product code `{77541DFC-2F8D-4531-AC0A-FA60804EDD0B}`, signed v15 MSI, clean disconnected network state.
- Produces: one v15 product registration, running agent service, no active connection mutation, and user test instructions.

- [ ] **Step 1: Prove the pre-upgrade baseline is safe**

Require service status known, exactly one v14 product registration, zero product/diagnostic rules, zero metrics `4096/8192` routes, zero product TUN, and absent `network-state.json`. Do not proceed on uncertain or nonzero state.

- [ ] **Step 2: Stop the service and normally uninstall exact v14**

```powershell
Stop-Service RegenBioOverseasAccessAgent
$p = Start-Process msiexec.exe -ArgumentList @('/x','{77541DFC-2F8D-4531-AC0A-FA60804EDD0B}','/qn','/norestart','/L*v',(Join-Path $env:TEMP 'RegenBio-OverseasAccess-v14-uninstall.log')) -Wait -PassThru
if ($p.ExitCode -notin 0,3010) { exit $p.ExitCode }
```

Expected: no v14 registration, service, Program Files root, product rules, routes, TUN, or state file.

- [ ] **Step 3: Install v15 and verify installed payload**

```powershell
$msi = (Resolve-Path 'dist/OverseasAccessSetup-POC-DIRECT-HTTP-v15-RELEASE_SIGNED.msi').Path
$p = Start-Process msiexec.exe -ArgumentList @('/i',$msi,'/qn','/norestart','/L*v',(Join-Path $env:TEMP 'RegenBio-OverseasAccess-v15-install.log')) -Wait -PassThru
if ($p.ExitCode -notin 0,3010) { exit $p.ExitCode }
```

Verify exactly one new product code, service initially stopped/manual, manifest source commit and mode, every installed file hash, every required Authenticode signer, and no network residue.

- [ ] **Step 4: Start the v15 service and rerun the LocalSystem transaction gate**

Start the service, wait five seconds, require it remains `Running`, stop it only while the gate executes if the gate requires exclusive state, run Task 3 Step 6, then restart it. Expected: gate success and clean disconnected baseline.

- [ ] **Step 5: Hand off one real connection attempt to the user**

Tell the user to fully exit FlClash, launch the newly installed RegenBio UI, click once, wait up to 30 seconds, and return copied diagnostics. If connected, the user tests an approved overseas site and corporate/internal access, then explicitly disconnects.

- [ ] **Step 6: Verify post-disconnect recovery before declaring completion**

After user confirmation, inspect service status, product registration, product rules, metrics `4096/8192` routes, product TUN, `network-state.json`, and sing-box child process. Expected: service may remain running, but all connection-owned state and child processes are absent. Only then mark the end-to-end objective complete.
