# Task 8 Installer Remediation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the Windows client package fail closed on untrusted MSI/payload content, own and resume lifecycle changes exactly, provision the DPAPI credential without disclosure, and emit reproducible provenance evidence.

**Architecture:** A first-party embedded verifier executable provides the MSI's pre-initialization Authenticode gate and post-copy signed-manifest gate. The PowerShell harness records exact resource ownership and monotonic durable phases. A separate stdin-only Go provisioner writes the fixed DPAPI credential, while a tracked PowerShell artifact recipe creates manifests, SBOM, checksums, and inspect-only or externally signed release packages.

**Tech Stack:** Go 1.27, Windows DPAPI, PowerShell 5.1/7, Pester 4-compatible tests, WiX 4.0.6, Windows Authenticode and CMS.

## Global Constraints

- Never execute the MSI or lifecycle harness against the live workstation.
- Never generate, persist, or commit a private signing key.
- Default artifacts are inspect-only and must abort before `InstallInitialize`.
- Release signing selects an existing out-of-repo certificate by thumbprint; no signing password is accepted in arguments or logs.
- Every production behavior begins with an observed failing test.
- No credential appears in MSI properties, argv, logs, registry, Git, or artifact evidence.

---

### Task 1: MSI trust and upgrade gates

**Files:**
- Create: `cmd/installer-verifier/main.go`
- Create: `cmd/installer-verifier/main_windows.go`
- Create: `cmd/installer-verifier/main_stub.go`
- Create: `cmd/installer-verifier/main_test.go`
- Modify: `deploy/client/Product.wxs`
- Modify: `deploy/client/Files.wxs`
- Modify: `tests/powershell/ClientInstall.Tests.ps1`

**Interfaces:**
- Consumes: MSI `OriginalDatabase`, compile-time corporate SHA-1 thumbprint, installed artifact manifest and detached CMS signature.
- Produces: `installer-verifier.exe package --msi <path> --thumbprint <sha1>` and `installer-verifier.exe payload --program-files <path> --program-data <path> --manifest <path> --signature <path> --thumbprint <sha1>`.

- [ ] Add Pester assertions that `VerifyPackageTrust` is an immediate Binary-table action before `InstallInitialize`, that `VerifyInstalledPayload` is deferred/no-impersonate after `InstallFiles` and before `InstallServices`, and that the default thumbprint is the inspect-only sentinel.
- [ ] Add Go tests for exact mode/argument validation, invalid thumbprint refusal, non-valid Authenticode result refusal, wrong signer refusal, invalid CMS refusal, missing/extra/hash-mismatched payload refusal, and generic errors.
- [ ] Run focused Pester and `go test ./cmd/installer-verifier`; confirm failures identify absent verifier/actions.
- [ ] Implement the verifier with dependency-injected command execution for portable tests and Windows PowerShell Authenticode/CMS/hash primitives for production.
- [ ] Add the verifier to the Binary table, schedule both checked gates, remove the upgrade exclusion from controlled disconnect, and schedule disconnect before old `StopServices`/file removal.
- [ ] Re-run focused tests and confirm GREEN.

### Task 2: Exact ownership and resumable lifecycle

**Files:**
- Modify: `deploy/client/install-client.ps1`
- Modify: `tests/powershell/ClientInstall.Tests.ps1`

**Interfaces:**
- Consumes: exact fixed roots, service, shortcut, firewall names, signed payload manifest.
- Produces: root marker `.regenbio-overseas-access.owner.json`, durable journal records with `Phase`, `CreatedResources`, and `PendingResources`, resumable `Install`, `Repair`, and `Uninstall`.

- [ ] Add behavioral/static Pester tests for foreign root/shortcut/service/firewall collision refusal, marker-before-content ordering, per-resource write-ahead entries, partial repair resume, partial uninstall resume, and owner/journal deletion only after residue proof.
- [ ] Run focused Pester and confirm the new tests fail for the missing ownership/phase semantics.
- [ ] Add collision preflight and exact marker validation; never put an ownership claim in a pre-existing directory.
- [ ] Replace whole-root ownership with exact files/resources and update the journal atomically before each creation/removal.
- [ ] Make repair/uninstall phase-driven and idempotent; compensate install failures in reverse order, retain proof on incomplete cleanup, and delete proof last after residue assertions.
- [ ] Leave service stopped when the fixed credential file is absent.
- [ ] Re-run focused Pester and confirm GREEN.

### Task 3: Stdin-only credential provisioner

**Files:**
- Create: `cmd/credential-provisioner/main.go`
- Create: `cmd/credential-provisioner/main_windows.go`
- Create: `cmd/credential-provisioner/main_stub.go`
- Create: `cmd/credential-provisioner/main_test.go`
- Create: `deploy/client/PROVISIONING.md`
- Modify: `deploy/client/Files.wxs`
- Modify: `tests/powershell/ClientInstall.Tests.ps1`

**Interfaces:**
- Consumes: one bounded JSON document from non-terminal standard input.
- Produces: DPAPI machine blob at `C:\ProgramData\RegenBio\OverseasAccess\credential.bin` through `secret.StoreMachine`; generic success/failure only.

- [ ] Add Go tests that reject args, terminal stdin, empty/oversize/malformed/multi-document input, zero the input buffer, call `StoreMachine` only at the fixed path, and never expose input in output/errors.
- [ ] Add Pester assertions that MSI contains the provisioner and procedure, has no credential property/action argv, and does not start the service before provisioning.
- [ ] Run the new Go/Pester tests and observe RED.
- [ ] Implement the portable runner plus Windows main, using `secret.StoreMachine`, bounded stdin, strict JSON validation, and buffer clearing.
- [ ] Document an elevated pipeline procedure that supplies the JSON through stdin, verifies service/admin-only ACL, then starts the service and confirms disconnected initial state.
- [ ] Re-run tests and confirm GREEN.

### Task 4: Signed artifact manifest, SBOM, license, and inspection recipe

**Files:**
- Create: `deploy/client/build-lock.json`
- Create: `deploy/client/checksums.lock`
- Create: `scripts/windows/build-client-artifacts.ps1`
- Create: `scripts/windows/inspect-client-msi.ps1`
- Modify: `Makefile`
- Modify: `deploy/client/Files.wxs`
- Modify: `.gitignore`
- Modify: `tests/powershell/ClientInstall.Tests.ps1`

**Interfaces:**
- Consumes: pinned archives, built first-party binaries, optional existing signing-certificate thumbprint and `signtool` path.
- Produces: staged `artifact-manifest.json`, `artifact-manifest.json.p7s`, `client-sbom.json`, `SHA256SUMS`, distinct `wintun-LICENSE.txt`, inspect-only MSI, or externally signed release MSI.

- [ ] Add Pester tests for exact lock versions/hashes, no network acquisition, distinct Wintun license attribution, canonical manifest/SBOM/checksum fields, inspect-only sentinel behavior, release-input requirements, recursive secret scan, and extracted-byte/hash/signature comparison.
- [ ] Run focused Pester and observe RED.
- [ ] Implement the tracked staging recipe: verify archive hashes and Wintun signature, build exact files, emit canonical metadata tied to `git rev-parse HEAD`, sign first-party binaries/manifest/MSI only with an existing external certificate, and emit an invalid unmistakable CMS sentinel in inspect-only mode.
- [ ] Implement raw-table/extraction inspection with exact allowlists, signature/hash comparisons, and recursive content/filename secret scanning.
- [ ] Wire `inspect-msi` and `release-msi` targets without adding download-at-install behavior.
- [ ] Re-run focused tests and confirm GREEN.

### Task 5: Full verification and evidence

**Files:**
- Modify: `.superpowers/sdd/task-8-report.md`

**Interfaces:**
- Consumes: all Task 8 remediation outputs.
- Produces: commit hashes, test evidence, MSI hash/table evidence, and explicit release blockers.

- [ ] Run focused Pester under Windows PowerShell 5.1 and PowerShell 7.
- [ ] Run full Pester, `go test ./...`, `go vet ./...`, and Windows builds.
- [ ] Build inspect-only MSI, decompile/extract it, compare every payload byte, query raw MSI ordering/ACL/service/firewall/upgrade/custom-action tables, and prove the package trust gate precedes `InstallInitialize`.
- [ ] Verify the inspect-only MSI is unsigned and that its authored gate therefore refuses release use; do not install it.
- [ ] Run `git diff --check` and recursively scan tracked/package content for keys and plaintext credentials.
- [ ] Update the Task 8 report with exact evidence and remaining corporate-signing/disposable-host gates.
- [ ] Commit remediation with message `fix: fail closed in Windows client installer`.
