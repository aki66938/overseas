# Task 10 Final Trust-Boundary Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Eliminate self-authorized direct provisioning, ambiguous SSH known-host trust, and incomplete WhatIf firewall comparison without live mutation.

**Architecture:** Extend the direct helper with a fixed external four-hash contract while leaving signed-driver lifecycle execution unchanged. Replace keyscan-derived trust with one independently approved Ed25519 public-key line and make the canonical VM snapshot enumerate the exact three server firewall rules plus every stable associated filter.

**Tech Stack:** Go 1.27, Windows PowerShell 5.1/PowerShell 7, Pester 3.4, OpenSSH, Windows firewall CIM cmdlets.

## Global Constraints

- Never set `OVERSEAS_ACCESS_INTEGRATION=1` or execute VM/host mutation.
- Expected hashes originate only in the verified signed contract or independent operator ledger, never the files under verification.
- Every production/runbook behavior change follows a witnessed focused RED then GREEN.
- Credentials remain absent from files, argv, environment, evidence, and logs.

---

### Task 1: Externally authorize direct credential provisioning

**Files:**
- Modify: `tests/integration/fixtureaction/action.go`
- Modify: `tests/integration/fixtureaction/action_test.go`
- Modify: `tests/integration/fixtureaction/main_windows.go`
- Modify: `tests/integration/fixtureaction/main_windows_test.go`
- Modify: `docs/sing-box-poc-runbook.md`
- Modify: `tests/powershell/Runbook.Tests.ps1`

**Interfaces:**
- Consumes: exact CLI flags `--expected-action-config-sha256`, `--expected-client-config-sha256`, `--expected-credential-source-sha256`, and `--expected-server-attestation-sha256`.
- Produces: fail-closed parsing and direct provisioning only after all external bindings match.

- [ ] Add Go tests for exact CLI parsing, substituted action-config bytes, substituted generated config/source/attestation, and internal/external hash disagreement.
- [ ] Run focused fixtureaction tests and observe failures from the missing trust contract.
- [ ] Implement external hash parsing, pre-parse byte hashing, strict attestation validation, and pre-execution source verification.
- [ ] Run focused fixtureaction tests to GREEN.
- [ ] Add Pester expectations for four fail-closed externally sourced placeholders and the exact helper command; observe RED.
- [ ] Update the runbook invocation and trust-source wording, then run focused Pester to GREEN.

### Task 2: Single independently approved SSH key

**Files:**
- Modify: `docs/sing-box-poc-runbook.md`
- Modify: `tests/powershell/Runbook.Tests.ps1`

**Interfaces:**
- Consumes: one approved `DESKTOP-1BVR2H6 ssh-ed25519 <base64>` line plus one separately approved SHA256 fingerprint.
- Produces: one exclusive ordinary known_hosts file and one exact fingerprint used by all SSH calls and attestation.

- [ ] Add Pester expectations rejecting keyscan, multiple lines/tokens/fingerprints, wrong host/type, and missing Ed25519 algorithm pin; observe RED.
- [ ] Implement exclusive one-line known_hosts construction, ordinary-file checks, exact single fingerprint validation, and uniform SSH options.
- [ ] Run focused Pester to GREEN.

### Task 3: Complete exact-name firewall WhatIf surface

**Files:**
- Modify: `docs/sing-box-poc-runbook.md`
- Modify: `tests/powershell/Runbook.Tests.ps1`

**Interfaces:**
- Consumes: the three fixed server firewall rule names.
- Produces: stable canonical rule/description/application/port/address/service/interface/security records in before/after snapshots.

- [ ] Add Pester expectations for exact names, every filter cmdlet, ownership Description, and rejection of Group selection; observe RED.
- [ ] Replace Group-based projection with exact-name deterministic complete filter capture and duplicate refusal.
- [ ] Run focused Pester to GREEN.

### Task 4: Report, full verification, and commit

**Files:**
- Modify: `.superpowers/sdd/task-10-report.md`

**Interfaces:**
- Consumes: fresh verification output.
- Produces: accurate non-live report, local commit, and clean worktree.

- [ ] Run locked full Go tests, vet, and the locked 20x repetition suite.
- [ ] Run PowerShell 5.1 and PowerShell 7 full Pester suites.
- [ ] Build the eight locked Windows amd64 binaries.
- [ ] Run AST, diff, and secret scans; inspect the complete diff.
- [ ] Correct the report, mark this plan complete, commit, and prove empty `git status --short`.
