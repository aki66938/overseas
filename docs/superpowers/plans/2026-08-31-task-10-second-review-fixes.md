# Task 10 Second-Review Fixes Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [x]`) syntax for tracking.

**Goal:** Close the second-review false-pass gaps in the non-live Task 10 Windows physical-host acceptance procedure without executing any live infrastructure mutation.

**Architecture:** Keep the signed protocol-v4 fixture as the trust boundary. Strengthen the strict Go contracts for remote attestation and credential provisioning, add a real staged pre-install verifier mode to the existing verifier binary, and make the operator runbook invoke only executable, pinned flows. Static Pester tests bind the runbook to those implementations while Go unit tests cover strict parsing, argument routing, and signed-contract validation.

**Tech Stack:** Go 1.27, Windows PowerShell 5.1/PowerShell 7, Pester 3.4, Windows SCM/CIM, OpenSSH known_hosts, detached CMS, Authenticode, sing-box 1.13.19.

## Global Constraints

- Do not set `OVERSEAS_ACCESS_INTEGRATION=1` or run any live VM/host mutation.
- Every production-code change follows a witnessed RED then GREEN focused test.
- Credentials never enter fixture/config staging files, argv, environment variables, evidence, or logs.
- The SSH target is exactly `Administrator@DESKTOP-1BVR2H6`, with Ed25519 host-key verification through a run-owned known_hosts file.
- The standard-client gate uses pinned sing-box `1.13.19` with `run -c stdin` and no secret-bearing temporary file.
- Final verification is the locked full Go test/vet gate, locked 20x repetition set, both Pester suites, eight locked Windows builds, AST parse, diff check, and secret scans.

---

### Task 1: Strict remote-attestation contract

**Files:**
- Modify: `tests/integration/fixtureconfig/config.go`
- Modify: `tests/integration/fixtureconfig/config_test.go`
- Modify: `tests/integration/fixturedriver/main_windows.go`
- Modify: `tests/integration/fixturedriver/main_windows_test.go`

**Interfaces:**
- Consumes: signed action/driver configuration, fixture manifest, current UTC time.
- Produces: `ServerAttestation.ValidateAt(..., expectedRunNonce string, now time.Time) error`, with `Validate` delegating to current UTC time.

- [x] Add tests whose valid attestation contains a 43-character OpenSSH SHA256 fingerprint and run nonce, then reject wrong hostname, stale/future time, wrong nonce, non-canonical server paths, listener/core path divergence, and malformed fingerprint.
- [x] Run the fixtureconfig focused test and observe failures caused by absent nonce/freshness/fixed-path behavior.
- [x] Add `run_nonce` to the strict flat schema, bind `DESKTOP-1BVR2H6`, enforce the three fixed server paths, enforce listener image path equals core path, enforce the exact OpenSSH fingerprint grammar, and use a 24-hour maximum age with five-minute future skew.
- [x] Thread the expected run nonce through strict action/driver config matching and remote-attestation validation.
- [x] Run fixtureconfig and fixturedriver tests to GREEN.

### Task 2: Executable pre-install bundle verifier

**Files:**
- Modify: `cmd/installer-verifier/main.go`
- Modify: `cmd/installer-verifier/main_test.go`
- Modify: `cmd/installer-verifier/main_windows.go`
- Create: `cmd/installer-verifier/main_windows_test.go`

**Interfaces:**
- Consumes: staged verifier pinned outside the bundle; MSI, release bundle, fixture/release manifests and detached signatures; exact SHA256 hashes, source commit, and three signer thumbprints.
- Produces: `verify-bundle` command and sanitized JSON evidence after every trust check succeeds.

- [x] Add portable routing tests for the exact fixed `verify-bundle` argument sequence and rejection before verifier dispatch when any value is absent/malformed.
- [x] Run installer-verifier tests and observe the new command fail as unsupported.
- [x] Extend `trustVerifier` with `verifyBundle(bundleInput) error` and route only the exact argument grammar.
- [x] Implement the Windows verifier script to verify MSI Authenticode/hash, both detached CMS signatures and manifest hashes, strict release schema/source commit/exact 16-file allowlist/destinations/hashes/signers, staged payload hashes/AuthentiCode, strict fixture top-level/artifact schema, and exclusive evidence publication.
- [x] Add a Windows static test that asserts the script contains every cryptographic/schema/payload gate and contains no MSI invocation.
- [x] Run installer-verifier tests to GREEN.

### Task 3: Connected anonymous-pipe provisioning contract

**Files:**
- Modify: `cmd/credential-provisioner/main.go`
- Modify: `cmd/credential-provisioner/main_test.go`
- Modify: `tests/integration/fixtureaction/action.go`
- Modify: `tests/integration/fixtureaction/action_test.go`
- Modify: `tests/integration/fixtureaction/main_windows.go`
- Modify: `tests/integration/fixtureaction/main_windows_test.go`

**Interfaces:**
- Consumes: signed method, endpoint, and exact RFC3339 expiry from the action config; a pinned credential source that writes one bounded JSON document to stdout.
- Produces: anonymous-pipe source-to-provisioner orchestration; provisioner strict document fields `method`, `endpoint`, `password`, `expires_at` matching fixed non-secret CLI contract arguments.

- [x] Add provisioner tests rejecting missing endpoint, contract mismatch, malformed contract arguments, terminal input, and extra JSON while keeping output generic.
- [x] Run credential-provisioner tests and observe failures from the absent expected-contract interface.
- [x] Extend the provisioner argument parser and document validation to compare exact method/endpoint/expiry before storing.
- [x] Add fixtureaction plan tests that require exact non-secret source/provisioner argument vectors and reject expired config.
- [x] Run fixtureaction tests and observe absent argument-vector behavior.
- [x] Pass the same signed contract to source and provisioner, connect source stdout directly to provisioner stdin with `os.Pipe`, give no parent stdin/env secret, discard source/provisioner output, close all inherited pipe ends deterministically, and kill/wait the peer on launch failure.
- [x] Run credential-provisioner and fixtureaction tests to GREEN.

### Task 4: Runbook executable safety flows

**Files:**
- Modify: `docs/sing-box-poc-runbook.md`
- Modify: `tests/powershell/Runbook.Tests.ps1`

**Interfaces:**
- Consumes: exact Go schemas and executable commands from Tasks 1-3.
- Produces: copy/paste-safe SSH attestation, canonical WhatIf comparison, staged verifier invocation, stdin-only standard client, and exact process capture.

- [x] Add Pester expectations for every flat attestation field, exact host/path/nonce/freshness binding, verified known_hosts fingerprint reuse, and strict SSH options; observe RED.
- [x] Rewrite attestation capture to emit the strict flat JSON schema from one authenticated SSH session and locally verify its hash/fingerprint/run nonce before use.
- [x] Add Pester expectations that WhatIf snapshots cover sorted filesystem/registry/tasks/server service/firewall state while excluding timestamps, full process inventories, and network probes; observe RED.
- [x] Replace the volatile WhatIf command with a stable canonical state command and executable before/after comparison.
- [x] Add Pester expectations for externally pinned staged verifier hash/signature, `artifact-manifest.json`, exact hashes/commit/signers, and verifier-before-MSI ordering; observe RED.
- [x] Update the custom-MSI gate to invoke the real `verify-bundle` command from the clean-host staging path.
- [x] Add Pester expectations for sing-box `1.13.19`, `run -c stdin`, redirected process stdin, readiness polling, process-handle cleanup, and absence of secret-bearing config staging; observe RED.
- [x] Rewrite the standard-client gate to hash/signature/version-check the binary and credentialless template, build the secret-bearing JSON only in memory, stream it to background sing-box stdin, and clean up in `finally`.
- [x] Add Pester expectations that agent capture uses SCM PID, core capture uses an exact child of the agent PID, and UI capture uses its own exact image PID; observe RED.
- [x] Replace the old service-PID-only helper with exact service/child/image capture modes.
- [x] Replace the fake PowerShell anonymous-pipe function with an invocation of the pinned Go action helper's `provision-credential` mode and its non-secret signed contract.
- [x] Run both Pester Runbook tests to GREEN.

### Task 5: Remove dead local-server implementation

**Files:**
- Modify: `tests/integration/fixtureaction/action.go`
- Modify: `tests/integration/fixtureaction/action_test.go`
- Modify: `tests/integration/fixtureaction/main_windows.go`

**Interfaces:**
- Consumes: remote-attestation-only topology.
- Produces: no compiled server install/remove/ownership functions on the physical-client action helper.

- [x] Add an AST/static test rejecting the dead local-server function names and ownership marker.
- [x] Run fixtureaction focused tests and observe RED.
- [x] Remove `serverPlan`, `productionServerPlan`, setup/verify/remove/ACL/copy/owner helpers, unused imports, constants, and obsolete tests.
- [x] Run fixtureaction focused tests to GREEN.

### Task 6: Report, locked verification, and commit

**Files:**
- Modify: `.superpowers/sdd/task-10-report.md`

**Interfaces:**
- Consumes: fresh command output from the full non-live gate.
- Produces: accurate non-live-only report and a clean commit.

- [x] Run focused tests again, then locked `go test -count=1 ./...`, locked `go vet ./...`, and the locked 20x repetition command.
- [x] Run full Windows PowerShell 5.1 and PowerShell 7 Pester suites.
- [x] Build the eight locked Windows amd64 binaries named in the Task 10 report.
- [x] Run PowerShell AST parse, `git diff --check`, private-key/bearer/PIN/password scans, and inspect the complete diff.
- [x] Update the report with only the evidence actually observed in this pass and retain the external live blockers.
- [x] Rerun any verification affected by the report edit, commit all scoped changes, and prove `git status --short` is empty.
