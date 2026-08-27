# Windows Forwarding Compatibility PoC Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build and run a reversible Go-based PoC that proves whether traffic from a WireGuard peer can be NATed by one Windows Server VM into the authenticated telecom client without leaking through the employee-network default gateway.

**Architecture:** A Go probe inventories interfaces, resolves approved test targets, runs source-aware connectivity checks, and emits a machine-readable verdict. Small PowerShell scripts apply and remove Windows forwarding/NAT/firewall state because those facilities are exposed through Windows networking cmdlets; all product logic and validation remain in Go.

**Tech Stack:** Go 1.26+, WireGuard for Windows, Windows Server 2022/2025, PowerShell 7+, `golang.org/x/sys/windows`, `gopkg.in/yaml.v3`, standard-library HTTP/DNS/network packages.

## Global Constraints

- Work only inside `C:/Users/Eleme/codex_workspace/overseas-access-gateway`.
- The telecom PIN remains on the Windows VM and is never read, stored, or automated by PoC code.
- Test only domains and IP addresses explicitly permitted by the telecom/operator whitelist.
- Employee and management subnets remain directly routed; only the WireGuard test subnet is eligible for PoC NAT.
- A telecom-client failure must close forwarding; forwarded traffic must never fall back to the employee-network internet gateway.
- Every networking change requires a deterministic rollback command and a saved pre-change snapshot.
- Do not begin the control plane or end-user client until Task 7 produces verdict `PASS`.

---

## File Map

- `go.mod`: Go module and pinned dependencies.
- `cmd/poc-probe/main.go`: CLI entry point for inventory, preflight, probe, and verdict commands.
- `internal/config/config.go`: strict YAML configuration loading and validation.
- `internal/config/config_test.go`: configuration validation tests.
- `internal/inventory/inventory.go`: Windows interface and route inventory abstraction.
- `internal/inventory/windows.go`: Windows implementation using PowerShell JSON output.
- `internal/inventory/inventory_test.go`: parsing and classification tests.
- `internal/probe/probe.go`: DNS, TCP, HTTPS, and source-route probe logic.
- `internal/probe/probe_test.go`: deterministic probe tests using local servers.
- `internal/verdict/verdict.go`: acceptance rules and JSON report model.
- `internal/verdict/verdict_test.go`: pass/fail decision tests.
- `configs/poc.example.yaml`: explicit example inputs and approved target schema.
- `scripts/windows/snapshot.ps1`: capture routes, adapters, NAT, and firewall state.
- `scripts/windows/apply-poc.ps1`: apply forwarding, NAT, and fail-closed rules.
- `scripts/windows/rollback-poc.ps1`: remove only PoC-owned state.
- `scripts/windows/assert-no-leak.ps1`: disable telecom path and verify no fallback.
- `docs/poc-runbook.md`: operator procedure, evidence checklist, and stop conditions.
- `artifacts/.gitkeep`: directory marker; generated evidence remains ignored.

### Task 1: Repository Skeleton and Strict Configuration

**Files:**
- Create: `go.mod`
- Create: `.gitignore`
- Create: `cmd/poc-probe/main.go`
- Create: `internal/config/config.go`
- Create: `internal/config/config_test.go`
- Create: `configs/poc.example.yaml`
- Create: `artifacts/.gitkeep`

**Interfaces:**
- Produces: `config.Load(path string) (config.Config, error)`
- Produces: `Config.Validate() error`
- `Config` fields: `WireGuardSubnet`, `WireGuardInterface`, `TelecomInterface`, `EmployeeInterface`, `InternalCIDRs`, `ApprovedTargets`, `ProbeTimeout`.

- [ ] **Step 1: Initialize the repository and module**

Run:

```powershell
Set-Location C:\Users\Eleme\codex_workspace\overseas-access-gateway
git init
go mod init corp.example/overseas-access-gateway
go get gopkg.in/yaml.v3@v3.0.1
```

Expected: an empty Git repository, `go.mod`, and `go.sum` exist.

- [ ] **Step 2: Write failing configuration tests**

Create tests covering: valid configuration; rejected empty interface names; rejected overlapping WireGuard/internal CIDRs; rejected non-HTTPS target; rejected timeout outside `1s..30s`.

```go
func TestValidateRejectsOverlappingCIDRs(t *testing.T) {
	cfg := validConfig()
	cfg.WireGuardSubnet = "10.77.0.0/24"
	cfg.InternalCIDRs = []string{"10.0.0.0/8"}
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected overlapping CIDRs to be rejected")
	}
}

func TestValidateRejectsHTTPProbeTarget(t *testing.T) {
	cfg := validConfig()
	cfg.ApprovedTargets = []Target{{Name: "bad", URL: "http://example.com/"}}
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected non-HTTPS target to be rejected")
	}
}
```

- [ ] **Step 3: Run tests and verify failure**

Run: `go test ./internal/config -v`

Expected: FAIL because `Config`, `Target`, and `Validate` do not exist.

- [ ] **Step 4: Implement strict configuration loading**

Implement typed YAML decoding with `KnownFields(true)`, `net/netip` CIDR parsing, overlap detection, HTTPS-only URLs, unique target names, and bounded timeouts. Return errors that name the invalid field without echoing secrets.

```go
type Config struct {
	WireGuardSubnet   string        `yaml:"wireguard_subnet"`
	WireGuardInterface string       `yaml:"wireguard_interface"`
	TelecomInterface  string        `yaml:"telecom_interface"`
	EmployeeInterface string        `yaml:"employee_interface"`
	InternalCIDRs     []string      `yaml:"internal_cidrs"`
	ApprovedTargets  []Target      `yaml:"approved_targets"`
	ProbeTimeout     time.Duration `yaml:"-"`
	ProbeTimeoutText string        `yaml:"probe_timeout"`
}

type Target struct {
	Name string `yaml:"name"`
	URL  string `yaml:"url"`
}
```

- [ ] **Step 5: Add CLI config validation and example configuration**

`poc-probe preflight --config configs/poc.yaml` loads configuration and prints either `PREFLIGHT_CONFIG_OK` or a single actionable error. The example must use documentation ranges and an operator-approved example hostname:

```yaml
wireguard_subnet: 10.77.0.0/24
wireguard_interface: wg-overseas-poc
telecom_interface: Telecom-Client
employee_interface: Ethernet
internal_cidrs:
  - 10.0.0.0/8
  - 172.16.0.0/12
  - 192.168.0.0/16
approved_targets:
  - name: operator-approved-test
    url: https://approved-test.example.invalid/
probe_timeout: 8s
```

- [ ] **Step 6: Run tests and commit**

Run: `go test ./internal/config -v`

Expected: PASS.

```powershell
git add go.mod go.sum .gitignore cmd internal/config configs artifacts
git commit -m "feat: add strict PoC configuration"
```

### Task 2: Windows Network Inventory

**Files:**
- Create: `internal/inventory/inventory.go`
- Create: `internal/inventory/windows.go`
- Create: `internal/inventory/inventory_test.go`
- Modify: `cmd/poc-probe/main.go`

**Interfaces:**
- Consumes: `config.Config` from Task 1.
- Produces: `inventory.Snapshot(ctx context.Context) (inventory.State, error)`.
- Produces: `inventory.Validate(state State, cfg config.Config) error`.

- [ ] **Step 1: Write failing JSON parsing and validation tests**

Use fixture JSON containing three adapters and routes. Assert exact alias matching, one ordinary default route, a present WireGuard prefix, and rejection when telecom and employee aliases resolve to the same interface index.

```go
func TestValidateRejectsSharedEmployeeAndTelecomInterface(t *testing.T) {
	state := State{Interfaces: []Interface{{Alias: "Ethernet", Index: 7, Status: "Up"}}}
	cfg := configForAliases("Ethernet", "Ethernet")
	if err := Validate(state, cfg); err == nil {
		t.Fatal("expected identical interface roles to be rejected")
	}
}
```

- [ ] **Step 2: Verify tests fail**

Run: `go test ./internal/inventory -v`

Expected: FAIL because inventory types and validation are undefined.

- [ ] **Step 3: Implement inventory collection**

Invoke `pwsh.exe -NoProfile -NonInteractive -Command` with a fixed script, never interpolated operator input. Read aliases from JSON output and match them in Go.

```powershell
$interfaces = Get-NetIPInterface | Select-Object InterfaceAlias,InterfaceIndex,AddressFamily,ConnectionState,Forwarding,NlMtu
$routes = Get-NetRoute | Select-Object InterfaceAlias,InterfaceIndex,DestinationPrefix,NextHop,RouteMetric,State
[pscustomobject]@{ interfaces = $interfaces; routes = $routes } | ConvertTo-Json -Depth 5 -Compress
```

- [ ] **Step 4: Add `inventory` CLI command**

`poc-probe inventory --config configs/poc.yaml --out artifacts/inventory-before.json` must write with create-new semantics so existing evidence cannot be silently overwritten.

- [ ] **Step 5: Run tests and commit**

Run: `go test ./internal/inventory -v`

Expected: PASS.

```powershell
git add cmd/poc-probe internal/inventory
git commit -m "feat: inventory Windows network state"
```

### Task 3: Approved-Target Connectivity Probe

**Files:**
- Create: `internal/probe/probe.go`
- Create: `internal/probe/probe_test.go`
- Modify: `cmd/poc-probe/main.go`

**Interfaces:**
- Consumes: `config.Target`, timeout, and optional source IP.
- Produces: `probe.Run(ctx context.Context, target config.Target, source net.IP) probe.Result`.
- `Result`: target name, resolved IPs, selected IP, TCP latency, TLS status, HTTP status, bytes, start/end timestamps, and normalized error code.

- [ ] **Step 1: Write failing local-server tests**

Use `httptest.NewTLSServer` and an injected resolver/dialer. Cover successful HTTPS, DNS failure, TCP timeout, TLS validation failure, and non-2xx HTTP response. Never call public internet targets from unit tests.

- [ ] **Step 2: Verify tests fail**

Run: `go test ./internal/probe -v`

Expected: FAIL because `Run` and `Result` do not exist.

- [ ] **Step 3: Implement bounded probes**

Use `net.Resolver.LookupNetIP`, a `net.Dialer{Timeout: timeout, LocalAddr: &net.TCPAddr{IP: source}}`, TLS 1.2 minimum, redirect disabled, and a response body cap of 64 KiB. Emit stable error codes: `dns_failed`, `tcp_failed`, `tls_failed`, `http_rejected`, `context_deadline`.

- [ ] **Step 4: Add probe CLI**

`poc-probe probe --config configs/poc.yaml --out artifacts/probe-telecom-up.json` probes only configured approved targets and writes JSON evidence.

- [ ] **Step 5: Run tests and commit**

Run: `go test ./internal/probe -v`

Expected: PASS.

```powershell
git add cmd/poc-probe internal/probe
git commit -m "feat: add approved-target connectivity probes"
```

### Task 4: Reversible Windows Forwarding Scripts

**Files:**
- Create: `scripts/windows/snapshot.ps1`
- Create: `scripts/windows/apply-poc.ps1`
- Create: `scripts/windows/rollback-poc.ps1`
- Create: `tests/powershell/PocNetworking.Tests.ps1`

**Interfaces:**
- Consumes: config values as explicit PowerShell parameters.
- Produces: NAT named `OverseasPocNat` and firewall rules in group `Overseas Gateway PoC`.
- Rollback removes only those exact owned resources.

- [ ] **Step 1: Write failing Pester static-safety tests**

Assert scripts use `SupportsShouldProcess`, reject empty aliases, use exact resource names, never call `Remove-NetNat` without `-Name OverseasPocNat`, and never disable all firewall profiles.

```powershell
It 'rollback only removes the owned NAT' {
    $text = Get-Content "$PSScriptRoot\..\..\scripts\windows\rollback-poc.ps1" -Raw
    $text | Should -Match 'Remove-NetNat\s+-Name\s+OverseasPocNat'
    $text | Should -Not -Match 'Remove-NetNat\s*(\r?\n|$)'
}
```

- [ ] **Step 2: Verify tests fail**

Run: `Invoke-Pester tests/powershell/PocNetworking.Tests.ps1 -Output Detailed`

Expected: FAIL because the scripts do not exist.

- [ ] **Step 3: Implement snapshot**

Capture `Get-NetIPInterface`, `Get-NetRoute`, `Get-NetNat`, `Get-NetFirewallRule`, `Get-NetFirewallAddressFilter`, and `Get-NetAdapter` to a timestamped JSON file under `artifacts`. Refuse to overwrite an existing snapshot.

- [ ] **Step 4: Implement apply script**

Validate all interfaces with `Get-NetAdapter -Name ... -ErrorAction Stop`; enable forwarding only on WireGuard and telecom interfaces; create `New-NetNat -Name OverseasPocNat -InternalIPInterfaceAddressPrefix <WireGuardSubnet>`; create explicit allow rules for WireGuard-to-telecom; create a higher-priority block for WireGuard-subnet traffic leaving the employee interface.

- [ ] **Step 5: Implement rollback script**

Remove firewall rules only where `Group -eq 'Overseas Gateway PoC'`, remove only NAT `OverseasPocNat`, and restore forwarding values from the snapshot. Abort if the snapshot lacks any required interface index.

- [ ] **Step 6: Run tests and commit**

Run: `Invoke-Pester tests/powershell/PocNetworking.Tests.ps1 -Output Detailed`

Expected: PASS.

```powershell
git add scripts/windows tests/powershell
git commit -m "feat: add reversible Windows PoC networking"
```

### Task 5: Fail-Closed Verdict Engine

**Files:**
- Create: `internal/verdict/verdict.go`
- Create: `internal/verdict/verdict_test.go`
- Create: `scripts/windows/assert-no-leak.ps1`
- Modify: `cmd/poc-probe/main.go`

**Interfaces:**
- Consumes: inventory-before, telecom-up probe, telecom-down probe, and inventory-after evidence.
- Produces: `verdict.Evaluate(Evidence) Report` with `PASS`, `FAIL`, or `INCONCLUSIVE`.

- [ ] **Step 1: Write failing verdict tests**

Cover: all allowed targets succeed while telecom is up and all fail while down => `PASS`; any target succeeds while telecom is down => `FAIL_LEAK`; missing evidence => `INCONCLUSIVE`; changed unrelated routes => `FAIL_STATE_DRIFT`.

```go
func TestEvaluateDetectsFallbackLeak(t *testing.T) {
	e := passingEvidence()
	e.TelecomDown.Results[0].Success = true
	r := Evaluate(e)
	if r.Status != "FAIL" || r.Code != "FAIL_LEAK" {
		t.Fatalf("got %#v", r)
	}
}
```

- [ ] **Step 2: Verify tests fail**

Run: `go test ./internal/verdict -v`

Expected: FAIL because verdict types are undefined.

- [ ] **Step 3: Implement deterministic evaluation**

Do not infer success from process state. Require network evidence: successful approved-target HTTPS while telecom is up; failed approved-target probes while telecom is down; no unrelated default-route or firewall drift after rollback.

- [ ] **Step 4: Implement no-leak orchestration script**

The script prompts the operator to disconnect the telecom client manually, confirms the telecom interface is down or its route absent, runs `poc-probe probe`, then prompts reconnection. It must not automate, read, or store the PIN.

- [ ] **Step 5: Add verdict CLI and commit**

Run:

```powershell
go test ./internal/verdict -v
go test ./...
```

Expected: all tests PASS.

```powershell
git add cmd/poc-probe internal/verdict scripts/windows/assert-no-leak.ps1
git commit -m "feat: add fail-closed PoC verdict"
```

### Task 6: Operator Runbook and Build Reproducibility

**Files:**
- Create: `docs/poc-runbook.md`
- Create: `Makefile`
- Modify: `.gitignore`

**Interfaces:**
- Produces: repeatable build, test, snapshot, apply, probe, no-leak, rollback, and verdict commands.

- [ ] **Step 1: Write the runbook with exact order and stop conditions**

The runbook must require: written operator approval; an operator-approved HTTPS target; VM console access; a recovery snapshot; current telecom PIN holder availability; and a maintenance window. Stop immediately if snapshot fails, an interface alias is ambiguous, NAT creation fails, internal routes change, or rollback verification fails.

- [ ] **Step 2: Add build and test targets**

```make
.PHONY: test build
test:
	go test ./...
	pwsh -NoProfile -Command "Invoke-Pester tests/powershell -Output Detailed"

build:
	go build -trimpath -o bin/poc-probe.exe ./cmd/poc-probe
```

- [ ] **Step 3: Document the execution sequence**

```powershell
Copy-Item configs\poc.example.yaml configs\poc.yaml
go run .\cmd\poc-probe preflight --config configs\poc.yaml
.\scripts\windows\snapshot.ps1
.\scripts\windows\apply-poc.ps1 -ConfigPath configs\poc.yaml -WhatIf
.\scripts\windows\apply-poc.ps1 -ConfigPath configs\poc.yaml
go run .\cmd\poc-probe probe --config configs\poc.yaml --out artifacts\probe-telecom-up.json
.\scripts\windows\assert-no-leak.ps1 -ConfigPath configs\poc.yaml
.\scripts\windows\rollback-poc.ps1 -SnapshotPath artifacts\<selected-snapshot>.json
go run .\cmd\poc-probe verdict --artifacts artifacts --out artifacts\verdict.json
```

The runbook must explain how to select the actual timestamped snapshot path instead of treating the angle-bracket notation as a literal filename.

- [ ] **Step 4: Verify clean build and commit**

Run:

```powershell
go test ./...
go build -trimpath -o bin\poc-probe.exe .\cmd\poc-probe
```

Expected: tests PASS and `bin/poc-probe.exe` exists.

```powershell
git add docs Makefile .gitignore
git commit -m "docs: add Windows forwarding PoC runbook"
```

### Task 7: Execute the Controlled PoC and Record the Gate Decision

**Files:**
- Create at runtime: `configs/poc.yaml`
- Create at runtime: `artifacts/inventory-before.json`
- Create at runtime: `artifacts/probe-telecom-up.json`
- Create at runtime: `artifacts/probe-telecom-down.json`
- Create at runtime: `artifacts/inventory-after.json`
- Create at runtime: `artifacts/verdict.json`
- Modify: `docs/poc-runbook.md` only if the observed platform requires a documented correction.

**Interfaces:**
- Consumes: all deliverables from Tasks 1-6 and an operator-approved target.
- Produces: evidence-backed decision to continue or stop product development.

- [ ] **Step 1: Fill real interface aliases and approved targets**

Use `Get-NetAdapter` and the telecom client UI to identify exact aliases. Do not guess interface names. Store `configs/poc.yaml` outside Git tracking.

- [ ] **Step 2: Capture baseline and verify rollback readiness**

Run snapshot, copy the snapshot to a second protected location, and run both apply and rollback with `-WhatIf`. Expected: only `OverseasPocNat`, the two selected forwarding flags, and firewall group `Overseas Gateway PoC` are targeted.

- [ ] **Step 3: Apply PoC networking and test with telecom connected**

Connect one WireGuard test peer, verify it receives an address from `10.77.0.0/24`, then run the approved-target probe. Expected: HTTPS succeeds and the observed public path matches the telecom line evidence supplied by the operator.

- [ ] **Step 4: Test fail-closed behavior**

Manually disconnect the telecom client, run the no-leak script, and verify every approved-target probe fails. Any successful forwarded connection is an immediate `FAIL_LEAK` and requires rollback.

- [ ] **Step 5: Roll back and compare state**

Run rollback, capture inventory-after, and verify ordinary employee connectivity, AD/DNS access, route tables, NAT objects, and firewall rules match the baseline except for expected timestamp/counter differences.

- [ ] **Step 6: Generate and review the verdict**

Run the verdict command. Expected outcomes:

- `PASS`: begin a separate service-control-plane implementation plan.
- `FAIL_LEAK`: stop; fix binding/firewall/NAT behavior before any client work.
- `FAIL_NO_FORWARD`: stop; ask the operator for gateway mode or SDK support.
- `INCONCLUSIVE`: repeat only the missing or invalid evidence step.

- [ ] **Step 7: Commit only code and documentation corrections**

Do not commit `configs/poc.yaml` or raw artifacts containing internal topology. If the runbook required a correction:

```powershell
git add docs/poc-runbook.md
git commit -m "docs: record validated PoC procedure"
```

## Plan Self-Review Result

- Spec coverage: this plan intentionally covers only the mandatory forwarding/fail-closed gate. AD enrollment, leases, production clients, audit storage, signed updates, and high availability require later plans after a `PASS` verdict.
- Placeholder scan: runtime-specific interface aliases, snapshot filenames, and approved targets are operator inputs with explicit discovery procedures; they are not implementation placeholders.
- Type consistency: configuration, inventory, probe, and verdict interfaces are defined before their consumers.

