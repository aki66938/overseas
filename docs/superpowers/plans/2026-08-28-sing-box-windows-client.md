# sing-box Windows One-Click Access Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build and validate a one-click Windows client whose Internet TCP traffic reaches the telecom HTTP CONNECT proxy on VM `172.20.9.15` through a fail-closed sing-box tunnel.

**Architecture:** A native Go UI talks over a locked-down named pipe to a LocalSystem Go service. The service validates policy and pinned binaries, renders a sing-box TUN configuration, supervises sing-box, and restores network state; the VM runs a separately managed sing-box server whose only proxy outbound is `127.0.0.1:8080`. The first release uses one revocable PoC credential and one node, while interfaces preserve a later transition to AD-issued short-lived credentials and multiple nodes.

**Tech Stack:** Go 1.27, `golang.org/x/sys/windows`, `github.com/Microsoft/go-winio`, `github.com/lxn/walk`, sing-box 1.13.19 Windows amd64, Shadowsocks 2022, PowerShell 5.1/7, Pester 3.4+, WiX Toolset v4, Windows Service Control Manager.

## Global Constraints

- The first deliverable supports Windows only and one node: `vm101` at `172.20.9.15`.
- The telecom upstream is HTTP CONNECT at `127.0.0.1:8080`; the project never reads, stores, fills, or distributes the government PIN.
- Corporate traffic, including `172.20.8.0/22`, AD, corporate DNS, EC, and the node address, remains direct.
- Internet TCP uses TUN; UDP/443 is rejected to force QUIC fallback; other Internet UDP is rejected in the PoC.
- Loss of the telecom upstream, server, tunnel, valid policy, or valid binary fails closed and never falls back to an ordinary Internet gateway.
- Closing, crashing, rebooting, or uninstalling restores routes, DNS, firewall state, services, and TUN state.
- TCP 8080 is reachable only from the VM itself; the sing-box port is reachable only from approved employee CIDRs; management ports are not employee-facing.
- Secrets use DPAPI and service-only ACLs; logs never contain PINs, proxy secrets, tokens, full URLs, or page content.
- Existing WireGuard/WinNAT files remain intact and continue passing their tests.
- No real networking mutation is allowed in unit tests. VM and physical-host mutation occurs only in the explicit deployment task after recording a baseline and confirming rollback commands.

---

## File Map

- `internal/accessmodel/model.go`: shared policy, node, credential, state, error-code types.
- `internal/accessmodel/validate.go`: strict semantic validation and canonical policy hashing.
- `internal/singconfig/server.go`: deterministic server JSON renderer.
- `internal/singconfig/client.go`: deterministic client TUN JSON renderer.
- `internal/coreverify/verify.go`: pinned SHA-256 and Authenticode verification boundary.
- `internal/secret/dpapi_windows.go`: machine-scoped DPAPI storage with service-only ACL.
- `internal/supervisor/process_windows.go`: child-process lifecycle and readiness supervision.
- `internal/agent/controller.go`: fail-closed connection state machine.
- `internal/agent/pipe_windows.go`: ACL-restricted named-pipe RPC server.
- `cmd/overseas-agent/main_windows.go`: Windows service entry point.
- `cmd/overseas-client/main_windows.go`: native one-toggle UI.
- `cmd/access-config/main.go`: offline policy/config generation and validation CLI.
- `deploy/server/install-server.ps1`: guarded VM install/update/rollback entry point.
- `deploy/server/server-policy.example.yaml`: non-secret VM policy example.
- `deploy/client/Product.wxs`: MSI definition.
- `deploy/client/install-client.ps1`: development install/uninstall harness.
- `tests/powershell/ServerInstall.Tests.ps1`: mocked server deployment safety tests.
- `tests/powershell/ClientInstall.Tests.ps1`: mocked client lifecycle tests.
- `tests/integration/fakeconnect/main.go`: controllable fake upstream/proxy process.
- `tests/integration/failclosed_windows_test.go`: Windows end-to-end lifecycle and leak tests.
- `docs/sing-box-poc-runbook.md`: operator deployment, rollback, evidence, and client instructions.

## Execution Prerequisite

The current development workstation previously reported that `go` was not available. Before Task 1, the executor must run `where.exe go`, `go version`, `pwsh -NoProfile -Command "$PSVersionTable.PSVersion"`, and `Get-Command Invoke-Pester`. If Go 1.27.x is unavailable, install the official Go 1.27.0 Windows amd64 MSI after recording its official SHA-256 and validating its Authenticode signature; then reopen the shell and require `go version` to report `go1.27.0 windows/amd64`. Install WiX v4 only before Task 8. A missing or unverifiable toolchain is a hard stop, not permission to skip RED/GREEN tests.

---

### Task 1: Shared Policy Contract and Strict Validation

**Files:**
- Create: `internal/accessmodel/model.go`
- Create: `internal/accessmodel/validate.go`
- Create: `internal/accessmodel/validate_test.go`
- Create: `cmd/access-config/main.go`
- Create: `cmd/access-config/main_test.go`
- Modify: `go.mod`

**Interfaces:**
- Produces: `accessmodel.Policy`, `Node`, `CredentialRef`, `RoutePolicy`, `Validate(Policy) error`, `CanonicalSHA256(Policy) (string, error)`.
- Produces: `access-config validate-policy -in .\configs\access-poc.yaml` and `access-config hash-policy -in .\configs\access-poc.yaml`.

- [ ] **Step 1: Add failing contract tests**

```go
func TestValidatePoCPolicy(t *testing.T) {
 p := accessmodel.Policy{SchemaVersion: 1, Mode: "poc", Nodes: []accessmodel.Node{{ID: "vm101", Address: "172.20.9.15", Port: 18443}}, CorporateCIDRs: []string{"172.20.8.0/22"}, BlockUDP: true, BlockQUIC: true, Credential: accessmodel.CredentialRef{Kind: "dpapi-file", Path: `C:\ProgramData\RegenBio\OverseasAccess\credential.bin`}}
 if err := accessmodel.Validate(p); err != nil { t.Fatal(err) }
}

func TestRejectsUnsafePolicy(t *testing.T) {
 cases := []accessmodel.Policy{
  {SchemaVersion: 1, Mode: "poc", Nodes: nil},
  {SchemaVersion: 1, Mode: "poc", Nodes: []accessmodel.Node{{ID: "vm101", Address: "172.20.9.15", Port: 18443}}, CorporateCIDRs: []string{"0.0.0.0/0"}},
  {SchemaVersion: 1, Mode: "poc", Nodes: []accessmodel.Node{{ID: "vm101", Address: "127.0.0.1", Port: 18443}}},
 }
 for i, p := range cases { if accessmodel.Validate(p) == nil { t.Fatalf("case %d accepted", i) } }
}
```

- [ ] **Step 2: Run RED**

Run: `go test ./internal/accessmodel ./cmd/access-config`

Expected: FAIL because packages and types do not exist.

- [ ] **Step 3: Implement exact shared types and validation**

```go
type Policy struct { SchemaVersion int `yaml:"schema_version" json:"schema_version"`; Mode string `yaml:"mode" json:"mode"`; Nodes []Node `yaml:"nodes" json:"nodes"`; CorporateCIDRs []string `yaml:"corporate_cidrs" json:"corporate_cidrs"`; CorporateDNS []string `yaml:"corporate_dns" json:"corporate_dns"`; InternalSuffixes []string `yaml:"internal_suffixes" json:"internal_suffixes"`; BlockUDP bool `yaml:"block_udp" json:"block_udp"`; BlockQUIC bool `yaml:"block_quic" json:"block_quic"`; Credential CredentialRef `yaml:"credential" json:"credential"` }
type Node struct { ID, Address string; Port uint16; Priority int }
type CredentialRef struct { Kind, Path string }
type ConnectionState string
const (StateDisconnected ConnectionState = "disconnected"; StateConnecting ConnectionState = "connecting"; StateConnected ConnectionState = "connected"; StateFailed ConnectionState = "failed")
```

`Validate` must reject unknown schema/mode, empty/duplicate nodes, loopback/multicast/unspecified node addresses, ports below 1024, empty corporate CIDRs, default routes in corporate CIDRs, a node covered by TUN without an explicit bypass, non-absolute credential paths, `BlockUDP=false`, and `BlockQUIC=false`. Decode YAML with `KnownFields(true)`, sort maps/slices for canonical JSON, and hash with SHA-256.

- [ ] **Step 4: Add CLI tests and implementation**

Test `validate-policy` exit codes: `0` valid, `2` usage, `3` invalid schema/input. Test `hash-policy` prints exactly 64 lowercase hexadecimal characters plus newline. Implement CLI with injected `io.Reader/io.Writer` and no network access.

- [ ] **Step 5: Run GREEN and regression suite**

Run: `go test ./internal/accessmodel ./cmd/access-config && go test ./...`

Expected: PASS for both commands, including all existing WireGuard/WinNAT tests.

- [ ] **Step 6: Commit**

```powershell
git add go.mod go.sum internal/accessmodel cmd/access-config
git commit -m "feat: define strict overseas access policy"
```

---

### Task 2: Deterministic sing-box Server and Client Configuration

**Files:**
- Create: `internal/singconfig/server.go`
- Create: `internal/singconfig/server_test.go`
- Create: `internal/singconfig/client.go`
- Create: `internal/singconfig/client_test.go`
- Modify: `cmd/access-config/main.go`
- Create: `deploy/server/server-policy.example.yaml`

**Interfaces:**
- Consumes: `accessmodel.Policy`, `accessmodel.Node`.
- Produces: `RenderServer(ServerInput) ([]byte, error)` and `RenderClient(ClientInput) ([]byte, error)`.
- Produces: `access-config render-server` and `render-client`, with secrets accepted only from stdin or an inherited handle, never command-line arguments.

- [ ] **Step 1: Write failing server renderer tests**

```go
func TestServerHasOnlyTelecomProxyPath(t *testing.T) {
 b, err := singconfig.RenderServer(singconfig.ServerInput{Listen: "0.0.0.0", Port: 18443, Method: "2022-blake3-aes-128-gcm", Password: "MDEyMzQ1Njc4OWFiY2RlZg==", Upstream: "127.0.0.1:8080"})
 if err != nil { t.Fatal(err) }
 s := string(b)
 for _, want := range []string{`"type":"shadowsocks"`,`"type":"http"`,`"server":"127.0.0.1"`,`"server_port":8080`,`"final":"telecom"`} { if !strings.Contains(s, want) { t.Fatalf("missing %s", want) } }
 if strings.Contains(s, `"type":"direct"`) { t.Fatal("server contains fallback direct outbound") }
}
```

- [ ] **Step 2: Run RED**

Run: `go test ./internal/singconfig`

Expected: FAIL because renderer does not exist.

- [ ] **Step 3: Implement server renderer**

Render one Shadowsocks 2022 inbound and one HTTP outbound tagged `telecom`; set route final to `telecom`; omit all direct Internet outbound. Validate upstream is exactly loopback TCP 8080 for the PoC and validate the decoded base64 key length required by the selected method.

- [ ] **Step 4: Write failing client renderer tests**

```go
func TestClientRoutesInternetTCPAndRejectsUDP(t *testing.T) {
 b, err := singconfig.RenderClient(singconfig.ClientInput{Node: accessmodel.Node{ID:"vm101",Address:"172.20.9.15",Port:18443}, CorporateCIDRs:[]string{"172.20.8.0/22"}, CorporateDNS:[]string{"172.20.10.1"}, InternalSuffixes:[]string{"ad.intra.regen-bio.com"}, Password:"MDEyMzQ1Njc4OWFiY2RlZg=="})
 if err != nil { t.Fatal(err) }
 assertJSONRule(t, b, "node-bypass", "172.20.9.15/32", "direct")
 assertJSONRule(t, b, "corp-direct", "172.20.8.0/22", "direct")
 assertJSONRule(t, b, "reject-quic", "udp", "443", "reject")
 assertJSONRule(t, b, "reject-udp", "udp", "", "reject")
 assertFinal(t, b, "tunnel")
}
```

- [ ] **Step 5: Implement client renderer and CLI**

Render a TUN inbound with automatic route disabled in favor of explicit controlled routes, strict route rules ordered as: node bypass, corporate CIDR/DNS direct, internal DNS suffix to corporate resolver, UDP/443 reject, remaining UDP reject, TCP to `tunnel`. Include no alternative direct rule for public TCP. Add CLI render subcommands that write atomically to a caller-specified path with service-only ACL instructions emitted separately.

- [ ] **Step 6: Verify generated configs with pinned sing-box**

Run: `go test ./internal/singconfig ./cmd/access-config`

Then run, using the pinned binary downloaded in Task 3: `sing-box.exe check -c <generated-server.json>` and `sing-box.exe check -c <generated-client.json>`.

Expected: all Go tests PASS and both checks exit 0.

- [ ] **Step 7: Commit**

```powershell
git add internal/singconfig cmd/access-config deploy/server/server-policy.example.yaml
git commit -m "feat: render fail-closed sing-box configs"
```

---

### Task 3: Pinned Core Acquisition and Verification

**Files:**
- Create: `internal/coreverify/verify.go`
- Create: `internal/coreverify/verify_test.go`
- Create: `scripts/fetch-sing-box.ps1`
- Create: `tests/powershell/FetchSingBox.Tests.ps1`
- Modify: `Makefile`

**Interfaces:**
- Produces: `Verify(path string, expectedSHA256 string, signerAllowlist []string) error`.
- Produces: `scripts/fetch-sing-box.ps1 -Version 1.13.19 -ExpectedSha256 $archiveSha256 -Destination $destination`, where `$archiveSha256` is copied from the official GitHub asset digest and checked into `sing-box.manifest.json` before the script can pass its tests.

- [ ] **Step 1: Add RED verification tests**

Create table tests for correct hash, mismatched hash, symlink/reparse-point rejection, directory rejection, writable-by-standard-users rejection, and a Windows test seam returning invalid Authenticode status.

Run: `go test ./internal/coreverify`

Expected: FAIL because `Verify` is undefined.

- [ ] **Step 2: Implement verifier**

Open the file without following reparse points, require a regular PE file owned by Administrators or SYSTEM, reject write ACEs for Users/Authenticated Users/Everyone, hash the already-open handle, compare using constant-time comparison, and call an injected Authenticode verifier. Production accepts only the explicitly documented sing-box signer/thumbprint discovered from the downloaded release; if the upstream binary is unsigned, require the pinned hash and record that fact in the runbook rather than pretending signature verification passed.

- [ ] **Step 3: Test the acquisition script before implementation**

Pester cases mock `Invoke-WebRequest`, hash calculation, archive expansion, and signature inspection. Assert download uses an official sing-box GitHub release URL, version and SHA are mandatory, mismatch removes the temporary directory, destination publication is atomic, and no existing binary is overwritten on failure.

Run: `Invoke-Pester tests/powershell/FetchSingBox.Tests.ps1`

Expected: FAIL because the script is absent.

- [ ] **Step 4: Implement and pin an exact release**

The script downloads the immutable `v1.13.19` Windows amd64 asset to a new temporary directory, verifies the official asset SHA-256 before expansion, locates exactly one `sing-box.exe`, runs `sing-box.exe version` and requires `1.13.19`, publishes with `Move-Item`, and writes `sing-box.manifest.json` containing version, archive hash, executable hash, signer status, acquisition URL, and UTC timestamp. The test must fail until the real 64-hex official asset digest has been recorded in the manifest; it must never accept an empty, sample, all-zero, or command-line-substituted digest.

- [ ] **Step 5: Verify**

Run: `go test ./internal/coreverify && Invoke-Pester tests/powershell/FetchSingBox.Tests.ps1 && make test && make build`

Expected: all tests PASS; `bin/access-config.exe`, `bin/overseas-agent.exe`, and `bin/overseas-client.exe` targets may remain pending until their tasks, but existing targets build.

- [ ] **Step 6: Commit**

```powershell
git add internal/coreverify scripts/fetch-sing-box.ps1 tests/powershell/FetchSingBox.Tests.ps1 Makefile
git commit -m "build: pin and verify sing-box core"
```

---

### Task 4: Secret Storage and Fail-Closed Process Supervisor

**Files:**
- Create: `internal/secret/dpapi_windows.go`
- Create: `internal/secret/dpapi_windows_test.go`
- Create: `internal/secret/dpapi_stub.go`
- Create: `internal/supervisor/process_windows.go`
- Create: `internal/supervisor/process_windows_test.go`
- Create: `internal/supervisor/process_stub.go`
- Create: `tests/integration/fakeconnect/main.go`

**Interfaces:**
- Produces: `secret.StoreMachine(path string, plaintext []byte) error`, `secret.LoadMachine(path string) ([]byte, error)`.
- Produces: `supervisor.Process.Start(ctx, exe, config string) error`, `Ready(ctx) error`, `Stop(ctx) error`, `Wait() error`.

- [ ] **Step 1: RED-test DPAPI and ACL behavior**

Test round-trip under the same machine context, corrupt ciphertext rejection, missing file, atomic replacement, file mode/ACL inspection, and zeroing the plaintext buffer after use. The non-Windows stub must return `ErrUnsupported`.

Run: `go test ./internal/secret`

Expected: FAIL because the package does not exist.

- [ ] **Step 2: Implement machine-scoped storage**

Use `CryptProtectData`/`CryptUnprotectData` with `CRYPTPROTECT_LOCAL_MACHINE`, entropy bound to `RegenBio/OverseasAccess/v1`, a temporary file in the same directory, and an ACL granting only SYSTEM and Administrators full control. Never return secret content in formatted errors.

- [ ] **Step 3: RED-test supervisor lifecycle**

Use `fakeconnect` modes `ready`, `exit-before-ready`, `hang-on-stop`, and `write-secret`. Assert readiness timeout kills the process, unexpected exit reports a typed failure, stop escalates from graceful shutdown to job-object termination, descendants die with the job, logs redact configured secret values, and a second `Start` is rejected.

Run: `go test ./internal/supervisor`

Expected: FAIL because the supervisor does not exist.

- [ ] **Step 4: Implement supervisor**

Launch only the verified absolute executable, pass only `run -c <absolute-config>` arguments, use a kill-on-close Windows job object, capture bounded stdout/stderr through a redactor, detect readiness through a local sing-box API or deterministic interface-presence probe, and implement idempotent stop. Do not invoke a shell.

- [ ] **Step 5: Verify and commit**

Run: `go test ./internal/secret ./internal/supervisor ./tests/integration/fakeconnect`

Expected: PASS on Windows; stubs compile on non-Windows.

```powershell
git add internal/secret internal/supervisor tests/integration/fakeconnect
git commit -m "feat: protect credentials and supervise sing-box"
```

---

### Task 5: Windows Service State Machine and Restricted IPC

**Files:**
- Create: `internal/agent/controller.go`
- Create: `internal/agent/controller_test.go`
- Create: `internal/agent/pipe_windows.go`
- Create: `internal/agent/pipe_windows_test.go`
- Create: `internal/agent/pipe_stub.go`
- Create: `cmd/overseas-agent/main_windows.go`
- Create: `cmd/overseas-agent/main_stub.go`

**Interfaces:**
- Consumes: policy validator, renderer, verifier, secret store, supervisor.
- Produces: `Controller.Connect(ctx) Status`, `Disconnect(ctx) Status`, `Status() Status`, `Diagnostics() Diagnostics`.
- Produces named-pipe JSON requests `{id,action}` where action is exactly `connect`, `disconnect`, `status`, or `diagnostics`; response is `{id,state,error_code,message}`.

- [ ] **Step 1: RED-test the controller transition table**

```go
func TestConnectFailureRemainsFailClosed(t *testing.T) {
 net := &fakeNetwork{blocked:true}; proc := &fakeProcess{startErr:errors.New("upstream unavailable")}
 c := agent.NewController(validPolicy(), net, proc)
 got := c.Connect(context.Background())
 if got.State != accessmodel.StateFailed || !net.blocked { t.Fatalf("got %#v blocked=%v", got, net.blocked) }
}

func TestDisconnectRestoresCapturedState(t *testing.T) {
 net := &fakeNetwork{blocked:true}; c := agent.NewController(validPolicy(), net, &fakeProcess{ready:true})
 c.Connect(context.Background()); got := c.Disconnect(context.Background())
 if got.State != accessmodel.StateDisconnected || net.blocked { t.Fatalf("got %#v", got) }
}
```

Also test concurrent connect coalescing, disconnect during connect, service restart reconciliation, invalid policy, bad binary, expired credential, readiness loss, and idempotent recovery.

- [ ] **Step 2: Run RED and implement minimal controller**

Run: `go test ./internal/agent -run Controller`

Expected: FAIL before implementation. Implement serialized transitions with a mutex and generation counter. The connect order is: validate inputs, capture original state, install public-TCP block, render config atomically, start core, wait ready, activate TUN routes, then mark connected. On every error, retain the public-TCP block until controlled cleanup or a successful tunnel exists.

- [ ] **Step 3: RED-test named-pipe authorization**

Test that Authenticated Users may connect but can invoke only the four fixed actions, anonymous/network logons are rejected, oversized and malformed frames close the connection, arbitrary executable/config fields are rejected, request IDs are echoed, and diagnostics are redacted.

Run: `go test ./internal/agent -run Pipe`

Expected: FAIL before pipe implementation.

- [ ] **Step 4: Implement pipe and Windows service entry point**

Use `go-winio` with a SDDL granting read/write to SYSTEM, Administrators, and interactive authenticated users while denying anonymous/network identities. Limit frames to 64 KiB, one JSON object per line, deadlines to 5 seconds, and actions to the fixed enum. Implement SCM start/stop controls; on service stop call controller disconnect and report nonzero service-specific exit if restoration fails.

- [ ] **Step 5: Verify and commit**

Run: `go test -race ./internal/agent && go test ./...`

Expected: all tests PASS.

```powershell
git add internal/agent cmd/overseas-agent go.mod go.sum
git commit -m "feat: add fail-closed Windows access service"
```

---

### Task 6: One-Toggle Native Windows UI

**Files:**
- Create: `internal/clientapi/client.go`
- Create: `internal/clientapi/client_test.go`
- Create: `cmd/overseas-client/main_windows.go`
- Create: `cmd/overseas-client/viewmodel.go`
- Create: `cmd/overseas-client/viewmodel_test.go`
- Create: `cmd/overseas-client/main_stub.go`

**Interfaces:**
- Consumes: named-pipe request/response contract from Task 5.
- Produces: `clientapi.Client.Connect`, `Disconnect`, `Status`, `Diagnostics` and a native Windows executable.

- [ ] **Step 1: RED-test API timeouts and response validation**

Test a 5-second connect deadline, mismatched request ID rejection, unknown state/error rejection, oversized response rejection, and that no secret/config fields are accepted or returned.

Run: `go test ./internal/clientapi`

Expected: FAIL before implementation.

- [ ] **Step 2: Implement the fixed pipe client**

Dial only `\\.\pipe\RegenBioOverseasAccess`, generate a cryptographically random request ID, send one action, decode one bounded response, and close. Do not accept a pipe path or arbitrary payload from UI arguments.

- [ ] **Step 3: RED-test view-model behavior**

Test the exact mapping: disconnected -> button `开启海外访问`; connecting -> disabled `正在连接`; connected -> `关闭海外访问`; failed -> `重试` plus one of the approved Chinese error messages. Test double-click suppression, close-window leaving the service connection unchanged, and diagnostics copying only redacted text.

Run: `go test ./cmd/overseas-client`

Expected: FAIL before implementation.

- [ ] **Step 4: Implement minimal native UI**

Use `walk` to create one fixed-size window containing title, status, one primary button, and “复制诊断信息”. Poll status every two seconds while visible. Do not show node, port, protocol, credential, autostart, or arbitrary settings. Closing the window exits the UI only; disconnect requires the explicit button.

- [ ] **Step 5: Build, smoke-test, and commit**

Run: `go test ./internal/clientapi ./cmd/overseas-client && go build -trimpath -ldflags "-H windowsgui" -o bin/overseas-client.exe ./cmd/overseas-client`

Expected: tests PASS; executable opens without a console and displays `未连接` when the service is absent.

```powershell
git add internal/clientapi cmd/overseas-client go.mod go.sum
git commit -m "feat: add one-toggle Windows access client"
```

---

### Task 7: Transactional Server Deployment

**Files:**
- Create: `deploy/server/install-server.ps1`
- Create: `tests/powershell/ServerInstall.Tests.ps1`
- Modify: `Makefile`

**Interfaces:**
- Consumes: pinned sing-box bundle, rendered server config, fixed VM facts.
- Produces: `Install`, `Status`, and `Rollback` modes with JSON evidence output and no implicit mutation.

- [ ] **Step 1: Write Pester RED tests**

Mock all native and Windows networking/service cmdlets. Assert `Install` refuses to continue unless: running elevated, OS is supported, VM address is `172.20.9.15`, telecom PID owns port 8080, an actual CONNECT probe through 8080 succeeds, server config passes `sing-box check`, hash verification succeeds, baseline evidence publication succeeds, and the employee CIDR/port are explicit. Assert `$?` and `$LASTEXITCODE` are both captured immediately after every native command. Assert `-WhatIf` makes no changes.

Run: `Invoke-Pester tests/powershell/ServerInstall.Tests.ps1`

Expected: FAIL because the script is absent.

- [ ] **Step 2: Implement staged install and rollback**

Install to `C:\Program Files\RegenBio\OverseasAccessServer`, secrets/config to `C:\ProgramData\RegenBio\OverseasAccessServer`, and create service `RegenBioOverseasAccessServer`. Before mutation, atomically record services, listeners, routes, firewall rules, process owner of 8080, hashes, config hash, and CONNECT result. Create exact named firewall rules for employee CIDR -> sing-box port, block remote access to 8080, and management restrictions. On any failure, compensate in reverse order. Rollback removes only transaction-tagged resources and restores captured originals.

- [ ] **Step 3: Add static safety contracts**

Pester parses the PowerShell AST and asserts one `SupportsShouldProcess`, no `Invoke-Expression`, no unguarded native invocation, no plaintext secret parameter, no wildcard deletion, exact service/firewall names, atomic evidence files, and a `finally` cleanup path.

- [ ] **Step 4: Verify and commit**

Run in both Windows PowerShell 5.1 and PowerShell 7:

```powershell
Invoke-Pester tests/powershell/ServerInstall.Tests.ps1
pwsh -NoProfile -Command "Invoke-Pester tests/powershell/ServerInstall.Tests.ps1"
```

Expected: both PASS with no real network mutation.

```powershell
git add deploy/server/install-server.ps1 tests/powershell/ServerInstall.Tests.ps1 Makefile
git commit -m "feat: add transactional sing-box server deployment"
```

---

### Task 8: Transactional Client Install and MSI

**Files:**
- Create: `deploy/client/install-client.ps1`
- Create: `deploy/client/Product.wxs`
- Create: `deploy/client/Files.wxs`
- Create: `tests/powershell/ClientInstall.Tests.ps1`
- Modify: `Makefile`

**Interfaces:**
- Consumes: agent, UI, pinned core, signed policy, TUN driver.
- Produces: `OverseasAccessSetup.msi`, development install/uninstall harness, service `RegenBioOverseasAccessAgent`.

- [ ] **Step 1: Add Pester RED lifecycle tests**

Assert install verifies all hashes/signatures before mutation, requires elevation, writes Program Files/ProgramData with restrictive ACLs, registers delayed-auto-start service with recovery actions, adds only exact firewall rules, creates shortcuts, and rolls back partial installs. Assert uninstall first requests controlled disconnect, refuses silent success when restoration fails, removes only owned resources, and leaves no service/TUN/route/DNS/firewall residue. Assert repair is idempotent and downgrade is rejected.

Run: `Invoke-Pester tests/powershell/ClientInstall.Tests.ps1`

Expected: FAIL before files exist.

- [ ] **Step 2: Implement development harness**

The script supports `Install`, `Repair`, `Uninstall`, and `Status`; uses exact absolute paths and transaction IDs; never downloads at install time; never places a plaintext secret in MSI properties, process arguments, logs, or registry; and calls the agent for restoration before removal.

- [ ] **Step 3: Implement WiX MSI**

Define per-machine x64 installation, major upgrade/downgrade prevention, service install/control, shortcuts, ARP metadata, embedded binaries, and deferred no-impersonate custom actions only where WiX native service/file features cannot suffice. Package a pre-encrypted PoC credential separately during controlled deployment; do not commit it to Git or embed its plaintext in the MSI.

- [ ] **Step 4: Verify package contents**

Run: `make test`, `make build`, `make msi`, then inspect the MSI table and extracted files. Expected: all tests PASS; MSI contains only expected executables, manifests, driver, policy, license metadata, and no plaintext credential or development key.

- [ ] **Step 5: Commit**

```powershell
git add deploy/client tests/powershell/ClientInstall.Tests.ps1 Makefile go.mod go.sum
git commit -m "build: package transactional Windows client installer"
```

---

### Task 9: Windows Fail-Closed Integration Harness

**Files:**
- Create: `tests/integration/failclosed_windows_test.go`
- Create: `tests/integration/README.md`
- Modify: `Makefile`

**Interfaces:**
- Consumes: built agent/client, fake upstream, generated configs.
- Produces: repeatable privileged test evidence without contacting the telecom service.

- [ ] **Step 1: Write an opt-in failing integration test**

Guard with `OVERSEAS_ACCESS_INTEGRATION=1` and elevation detection. Capture routes, DNS, adapters, services, processes, and owned firewall rules before each case. Cases are: connect success to fake upstream; upstream absent; upstream dies while connected; core exits; UI exits; service restarts; machine-style recovery invocation; 20 connect/disconnect cycles; and uninstall cleanup.

- [ ] **Step 2: Run RED on a disposable Windows test host**

Run: `$env:OVERSEAS_ACCESS_INTEGRATION='1'; go test -count=1 -v ./tests/integration`

Expected: at least one fail-closed/lifecycle assertion FAIL before remaining integration hooks are completed; baseline evidence is preserved.

- [ ] **Step 3: Complete integration hooks and assertions**

Every failure case must prove public TCP cannot reach a local “ordinary gateway” sentinel while the tunnel is unavailable, corporate CIDR sentinel remains reachable where intended, and final state exactly matches the captured baseline. The test must restore state in `defer`/`TestMain` and fail loudly if restoration cannot be proven.

- [ ] **Step 4: Run GREEN and stress repetitions**

Run: `$env:OVERSEAS_ACCESS_INTEGRATION='1'; go test -count=1 -v ./tests/integration` and `go test -count=20 ./internal/agent ./internal/supervisor`.

Expected: PASS with 20/20 lifecycle repetitions and zero state drift.

- [ ] **Step 5: Commit**

```powershell
git add tests/integration Makefile
git commit -m "test: prove Windows tunnel fails closed"
```

---

### Task 10: VM101 Deployment, Standard-Client Gate, and Physical-Client Acceptance

**Files:**
- Create: `docs/sing-box-poc-runbook.md`
- Create at runtime (gitignored): `artifacts/sing-box-poc/<UTC-run-id>/...`
- Modify: `.gitignore`

**Interfaces:**
- Consumes: server installer, standard sing-box client config, MSI, acceptance probes.
- Produces: sanitized evidence bundle, exact server facts, rollback record, and a PoC verdict.

- [ ] **Step 1: Write the runbook contract test first**

Extend `tests/powershell/Runbook.Tests.ps1` to require exact commands for SSH host-key pinning, baseline capture, telecom CONNECT proof, server WhatIf, server install, immediate `$?` and exit-code guards, status, rollback, standard-client configuration, MSI install, enable/disable, leak probes, and evidence collection. Require a stop/go checkpoint before each real mutation group.

Run: `Invoke-Pester tests/powershell/Runbook.Tests.ps1`

Expected: FAIL until the new runbook exists.

- [ ] **Step 2: Write and statically verify the runbook**

Document the known server facts (`172.20.9.15/22`, gateway `172.20.10.1`, interface index 4, SSH host `DESKTOP-1BVR2H6`, telecom upstream `127.0.0.1:8080`) without embedding SSH private keys or credentials. Every native command stores `$?` and `$LASTEXITCODE` immediately and aborts on either launch or process failure. Every mutating section begins with inventory and lists an exact rollback command.

- [ ] **Step 3: Record a fresh VM baseline and run WhatIf**

Connect using the already pinned SSH host key. Record OS, adapter, routes, DNS, listeners, service/process inventory, firewall, sing-box absence/presence, port 8080 owner, direct Google failure, and CONNECT-through-8080 success. Run server installer `-WhatIf`; compare baseline and prove zero changes.

- [ ] **Step 4: Deploy the VM server and prove the standard-client gate**

After the operator confirms the telecom PIN session is active, install the pinned server bundle and generated one-time PoC secret. First connect from a disposable physical Windows machine using the standard sing-box client config. Prove Google/approved site success, corporate access continuity, direct access to VM:8080 failure, service stop leak failure, telecom-process stop leak failure, and recovery after restart. Do not proceed to custom MSI until this gate passes.

- [ ] **Step 5: Install and accept the custom client**

Remove the standard client configuration, install `OverseasAccessSetup.msi`, and verify one-click enable/disable for browser, Git, HTTPS, corporate DNS, AD, and EC. Exercise service/core/UI termination, node loss, telecom loss, reboot, 20 toggles, and uninstall. Record timestamps, config/binary hashes, exact probe targets, exit codes, route/DNS/firewall snapshots, and redacted logs.

- [ ] **Step 6: Produce the verdict and rollback if any mandatory case fails**

PASS requires one full workday, all fail-closed tests, 20 clean cycles, no ordinary-exit fallback, no direct 8080 access, and exact final-state restoration. Any mandatory failure yields FAIL, invokes the documented rollback, verifies rollback state, and preserves evidence. Never label a partial test PASS.

- [ ] **Step 7: Commit only sanitized documentation**

```powershell
git add .gitignore docs/sing-box-poc-runbook.md tests/powershell/Runbook.Tests.ps1
git commit -m "docs: add sing-box PoC deployment and acceptance runbook"
```

Runtime credentials, raw user identifiers, SSH keys, PIN-related material, and unsanitized logs remain outside Git.

---

## Final Verification Gate

- [ ] Run `go test -race ./...` and require PASS.
- [ ] Run `go vet ./...` and require exit 0.
- [ ] Run `make build` and require all Windows binaries to build with pinned dependencies.
- [ ] Run the complete Pester suite under Windows PowerShell 5.1 and PowerShell 7 and require PASS.
- [ ] Run `git diff --check` and scan tracked content for private keys, PoC credentials, PINs, bearer tokens, and raw employee identifiers.
- [ ] Verify the old WireGuard/WinNAT tests still pass and their production files are unchanged except deliberately shared build/docs wiring.
- [ ] Compare the sanitized acceptance evidence to every requirement in the approved specification.
- [ ] Use `superpowers:verification-before-completion`, then `superpowers:requesting-code-review`, before claiming the implementation complete.
