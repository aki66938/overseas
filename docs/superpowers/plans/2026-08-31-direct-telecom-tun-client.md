# Direct Telecom TUN Client Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build, sign and install a Windows TUN client whose only overseas outbound is HTTP CONNECT to `172.20.9.15:8080`, leaving it disconnected for the user-run FlClash-off acceptance test.

**Architecture:** Add an explicit `http-connect` node transport to policy schema 2. The agent renders this transport without loading a DPAPI secret, while retaining the existing direct host route, corporate bypass, DNS hijack and fail-closed network controller. Schema 1 remains readable only for the repository's legacy Shadowsocks compatibility path; the new signed package contains schema 2 exclusively. Package it as a PoC-signed MSI, install without starting the service or changing proxy settings, and prepare a separately invoked recovery command for the user's live test.

**Tech Stack:** Go 1.27, sing-box 1.13.19, Windows Service Control Manager, Wintun, PowerShell 5.1/7, Pester 3.4, WiX 4.0.6, Windows SDK SignTool.

## Global Constraints

- The approved upstream is exactly IPv4 `172.20.9.15`, TCP port `8080`, transport `http-connect`.
- Schema 1 validation and credential behavior remain intact for legacy tests and artifacts; schema 2 requires `http-connect` and forbids a credential reference.
- VM101 is not modified by this plan; no RegenBio server service or TCP 18443 listener is deployed.
- Installation must leave `RegenBioOverseasAccessAgent` stopped and the UI disconnected.
- No step closes, reconfigures or otherwise mutates FlClash or Windows system proxy settings.
- Live TUN connection and overseas-site acceptance are performed by the user only after closing FlClash.
- Source and artifacts contain no telecom PIN, Shadowsocks key or other secret.
- New behavior follows strict RED, GREEN, refactor TDD.

---

### Task 1: Model and render an HTTP CONNECT node

**Files:**
- Modify: `internal/accessmodel/model.go`
- Modify: `internal/accessmodel/validate.go`
- Modify: `internal/accessmodel/validate_test.go`
- Modify: `internal/singconfig/client.go`
- Modify: `internal/singconfig/client_test.go`

**Interfaces:**
- Consumes: existing `accessmodel.Policy`, route/DNS validation and sing-box JSON renderer.
- Produces: `Node.Transport string`, policy schema 2, and `singconfig.RenderClient` output with an HTTP `tunnel` outbound.

- [ ] **Step 1: Write failing access-model tests**

Add cases proving schema 2 requires every node transport to equal `http-connect`, accepts only `172.20.9.15:8080` for this PoC, forbids a credential reference, and rejects empty, `shadowsocks`, loopback, wildcard, another address, or another port. Retain schema-1 acceptance tests for the legacy DPAPI/Shadowsocks policy. Update canonical-hash fixtures so `Transport` participates in the schema-2 digest.

- [ ] **Step 2: Run the focused model tests and witness RED**

Run:

```powershell
& scripts/windows/invoke-locked-client-tool.ps1 -Tool Go -ToolArguments @('test','-count=1','./internal/accessmodel')
```

Expected: FAIL because `Node.Transport` and schema 2 validation do not exist.

- [ ] **Step 3: Implement minimal schema-2 validation**

Add:

```go
type Node struct {
    ID string `yaml:"id" json:"id"`
    Transport string `yaml:"transport" json:"transport"`
    Address string `yaml:"address" json:"address"`
    Port uint16 `yaml:"port" json:"port"`
    Priority int `yaml:"priority" json:"priority"`
}
```

Dispatch validation by schema version: schema 1 retains the existing credential and node rules, while schema 2 rejects a nonempty credential, validates the exact approved transport/address/port tuple, and includes `Transport` in canonical node sorting.

- [ ] **Step 4: Run focused model tests and witness GREEN**

Run the Step 2 command. Expected: PASS.

- [ ] **Step 5: Write failing sing-box renderer tests**

Change the primary client test input to:

```go
Node: accessmodel.Node{ID: "vm101", Transport: "http-connect", Address: "172.20.9.15", Port: 8080}
```

Assert the second outbound is exactly:

```json
{"type":"http","tag":"tunnel","server":"172.20.9.15","server_port":8080}
```

and has no `method`, `password`, or `network`. Retain the first `172.20.9.15/32 -> direct` route assertion and add explicit rejection cases for loopback, wildcard and an unapproved endpoint.

- [ ] **Step 6: Run renderer tests and witness RED**

Run:

```powershell
& scripts/windows/invoke-locked-client-tool.ps1 -Tool Go -ToolArguments @('test','-count=1','./internal/singconfig')
```

Expected: FAIL because the renderer still requires and emits Shadowsocks credentials.

- [ ] **Step 7: Render the minimal HTTP outbound**

Remove `Method` and `Password` from `ClientInput`, remove method/password validation from `RenderClient`, and emit:

```go
clientOutbound{Type: "http", Tag: "tunnel", Server: nodeAddress, ServerPort: input.Node.Port}
```

Keep direct, DNS and route-rule behavior unchanged.

- [ ] **Step 8: Run both focused packages and commit**

Run both focused commands. Expected: PASS.

```powershell
git add internal/accessmodel internal/singconfig
git commit -m "feat: render direct telecom HTTP tunnel"
```

---

### Task 2: Make the Windows agent credentialless for HTTP CONNECT

**Files:**
- Modify: `internal/agent/controller.go`
- Modify: `internal/agent/controller_test.go`
- Modify: `cmd/overseas-agent/main_windows.go`
- Modify: `cmd/overseas-agent/main_windows_test.go`
- Modify: `deploy/client/agent.yaml`

**Interfaces:**
- Consumes: schema-2 policy and credentialless `singconfig.ClientInput` from Task 1.
- Produces: a controller dependency `RenderConfig func(accessmodel.Policy) ([]byte,error)` that performs no credential read.

- [ ] **Step 1: Write failing controller and Windows-agent tests**

Assert `Connect` reaches config rendering without invoking a credential loader; assert rendered config is HTTP CONNECT; assert `agent.yaml` uses schema 2, transport `http-connect`, address `172.20.9.15`, port `8080`, and contains no credential section or TCP 18443.

- [ ] **Step 2: Run focused tests and witness RED**

```powershell
& scripts/windows/invoke-locked-client-tool.ps1 -Tool Go -ToolArguments @('test','-count=1','./internal/agent','./cmd/overseas-agent')
```

Expected: FAIL because controller connection still loads and expires credentials.

- [ ] **Step 3: Remove credential loading from the connection boundary**

Change `Dependencies.RenderConfig` to accept only policy, delete `LoadCredential` and `Now` from the production connection path, and remove `credential_unavailable`/`credential_expired` decisions that are unreachable in the approved transport. Preserve policy validation, executable verification, atomic config publication, supervisor startup and fail-closed network ordering.

- [ ] **Step 4: Update the Windows agent renderer and bootstrap policy**

Make `renderClientConfig(policy)` select the priority node and pass it to the credentialless renderer. Update `deploy/client/agent.yaml` to the exact approved schema-2 policy and remove `credential`.

- [ ] **Step 5: Run focused tests and commit**

Run the Step 2 command. Expected: PASS.

```powershell
git add internal/agent cmd/overseas-agent deploy/client/agent.yaml
git commit -m "feat: connect Windows agent without tunnel credential"
```

---

### Task 3: Package a disconnected, proxy-neutral client

**Files:**
- Modify: `deploy/client/install-client.ps1`
- Modify: `deploy/client/Files.wxs`
- Modify: `deploy/client/PROVISIONING.md`
- Modify: `scripts/windows/build-client-artifacts.ps1`
- Modify: `scripts/windows/publish-client-release.ps1`
- Modify: `cmd/installer-verifier/main_windows.go`
- Modify: `tests/powershell/ClientInstall.Tests.ps1`
- Modify: `tests/powershell/Runbook.Tests.ps1`

**Interfaces:**
- Consumes: credentialless agent and schema-2 signed policy.
- Produces: an MSI with no credential provisioner payload or credential runtime file, installed service state `Stopped`, and no system-proxy/FlClash mutation.

- [ ] **Step 1: Write failing packaging tests**

Add assertions that the MSI payload and signed artifact manifest omit `credential-provisioner.exe` and `PROVISIONING.md`; installer cleanup supports only `sing-box.json`; no client installer/build script references `credential.bin`; installer contains no `netsh winhttp`, Internet Settings registry write, FlClash process/service operation, `Start-Service`, or automatic connect action; service installation uses start type manual and initial stopped state.

- [ ] **Step 2: Run dual focused Pester and witness RED**

```powershell
powershell.exe -NoProfile -Command "$r=Invoke-Pester -Script tests/powershell/ClientInstall.Tests.ps1 -PassThru; if($r.FailedCount){exit 1}"
pwsh -NoProfile -Command "$r=Invoke-Pester -Script tests/powershell/ClientInstall.Tests.ps1 -PassThru; if($r.FailedCount){exit 1}"
```

Expected: FAIL on credential payload/runtime ownership and packaging expectations.

- [ ] **Step 3: Remove credential-specific package surfaces**

Remove the credential provisioner file/component, build/sign/payload entries and provisioning document. Narrow runtime ownership and uninstall cleanup to `sing-box.json`. Keep release signature, payload hash, rollback, exact firewall ownership and trust-gate ordering intact.

- [ ] **Step 4: Add the operator handoff runbook**

Replace provisioning instructions with exact commands that verify installation and stopped state, record baseline hashes, create a user-invoked recovery task/script, and explicitly state that Codex does not close FlClash or start the tunnel. The live sequence must be: user closes FlClash, starts RegenBio UI/service, connects, tests, disconnects, then optionally restarts FlClash.

- [ ] **Step 5: Run dual focused Pester and commit**

Run both Step 2 commands plus focused Runbook Pester. Expected: PASS.

```powershell
git add deploy/client scripts/windows cmd/installer-verifier tests/powershell
git commit -m "build: package credentialless telecom TUN client"
```

---

### Task 4: Full verification, signed build and local installation

**Files:**
- Update: `.superpowers/sdd/task-10-report.md`
- Create outside repository: `C:\Users\Eleme\codex_workspace\.secrets\overseas-access-poc\client-install-baseline.json`
- Create outside repository: `C:\Users\Eleme\codex_workspace\.secrets\overseas-access-poc\restore-overseas-client.ps1`
- Produce ignored artifact: `dist/OverseasAccessSetup-POC-DIRECT-HTTP.msi`

**Interfaces:**
- Consumes: committed clean source, PoC certificate thumbprint `6A9D8BC41086C6B764B8C7439E797671EF83C15E`, locked Go/WiX toolchain, Microsoft SignTool.
- Produces: verified signed MSI, installed-but-stopped client, baseline evidence and a recovery command for the user-run test.

- [ ] **Step 1: Run the complete non-live regression matrix**

Run locked `go test -count=1 ./...`, locked `go vet ./...`, full Pester under Windows PowerShell 5.1 and PowerShell 7, eight Windows/amd64 builds, PowerShell AST parsing and `git diff --check`. Expected: all PASS and clean worktree after committing the report.

- [ ] **Step 2: Build and inspect the release payload/MSI**

Use `scripts/windows/publish-client-release.ps1` with the PoC certificate and the verified SDK SignTool. Require a valid MSI Authenticode signature, exact PoC signer thumbprint, exact extracted payload allowlist, signed-manifest hashes, schema-2 HTTP endpoint and absence of credential/Shadowsocks material.

- [ ] **Step 3: Capture the workstation baseline without changing it**

Record system proxy, WinHTTP proxy, active default routes, DNS servers, RegenBio service state, FlClash process/service state and product firewall rules in the protected baseline JSON. Hash the evidence and recovery script. Do not stop processes or alter routes.

- [ ] **Step 4: Install without starting the tunnel**

Run the signed MSI elevated with verbose logging. Require exit code 0, valid installed binary signatures/hashes, service `Stopped`, no RegenBio TUN adapter, no product-owned active routes, unchanged system/WinHTTP proxy, and unchanged FlClash state. If any postcondition fails, uninstall immediately and compare the captured baseline.

- [ ] **Step 5: Stage but do not execute recovery**

Create a protected script that stops `RegenBioOverseasAccessAgent`, invokes the product restore path, verifies removal of owned TUN routes/DNS/firewall state, and leaves FlClash untouched. Give the user the exact elevated command to schedule/run it before live acceptance.

- [ ] **Step 6: Hand off live acceptance to the user**

Report the MSI SHA-256, signer, installation log, installed service/UI state and recovery command. Instruct the user to close FlClash, arm recovery, connect from the RegenBio UI, test applications without proxy settings, disconnect, and report results. Do not claim live acceptance before their response.
