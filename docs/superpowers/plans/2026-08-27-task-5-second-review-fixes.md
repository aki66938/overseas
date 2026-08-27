# Task 5 Second Review Fixes Implementation Plan

> **For agentic workers:** Apply strict test-driven development. Do not execute real networking.

**Goal:** Close the remaining inventory-schema and Windows native-process race/cleanup gaps without weakening create-new evidence or PIN isolation.

**Architecture:** Expand the canonical inventory model to cover stable WinNAT behavior/timeouts and every material Windows Firewall rule/filter dimension. Custom JSON unmarshalling rejects omitted required fields while retaining explicit empty collections. The no-leak gate holds a deny-write/delete file handle from identity verification through both native launches, continuously polls the telecom path, and always terminates/reaps a live child before the reconnect prompt.

**Tech Stack:** Portable Go 1.27 standard library, Windows PowerShell 5 / PowerShell 7, Pester 3.4.

## Constraints

- Use fixtures, local fake PE files, mocks, and fake process objects only.
- Do not change a real interface, route, NAT, firewall rule, or telecom-client state.
- Preserve create-new evidence writes and never read, store, or automate the telecom PIN.

### Task 1: Complete and presence-aware inventory evidence

**Files:**
- Modify: `internal/inventory/inventory.go`
- Modify: `internal/inventory/windows.go`
- Modify: `internal/inventory/inventory_test.go`
- Modify: `internal/verdict/verdict.go`
- Modify: `internal/verdict/verdict_test.go`
- Modify: `cmd/poc-probe/main_test.go`

- [ ] Add RED tests for WinNAT filtering/timeouts and firewall edge, interface-type, ICMP, dynamic-target, package/app-container, security, and stable rule-policy fields.
- [ ] Add RED tests proving omitted state arrays and omitted firewall filter arrays/fields are invalid while explicit empty arrays remain valid.
- [ ] Implement strict custom JSON unmarshalling and normalized Windows collection.
- [ ] Extend canonical comparison and structural validation, then run focused GREEN tests.

### Task 2: Lock executable identity and make child cleanup fail closed

**Files:**
- Modify: `scripts/windows/assert-no-leak.ps1`
- Modify: `tests/powershell/AssertNoLeak.Tests.ps1`

- [ ] Add RED behavioral tests proving the PE is locked against write/delete during `describe-config` and `probe`, and released afterward.
- [ ] Add RED multi-poll tests for repeated `WaitForExit($false)`, intermediate reconnect, polling exceptions, and child kill/wait ordering before the reconnect prompt.
- [ ] Hold a read-only sharing handle across verification and both launches; always clean up a live child in the post-disconnect `finally` before prompting reconnection.
- [ ] Preserve primary polling errors where possible while still surfacing cleanup/restore failures fail closed.
- [ ] Run focused GREEN Pester 3.4 under PowerShell 7 and Windows PowerShell 5.

### Task 3: Verification and handoff

**Files:**
- Modify: `.superpowers/sdd/task-5-report.md`
- Modify: `.superpowers/sdd/task-5-review-package-r2.md`

- [ ] Run gofmt, full Go tests, vet, build, both Pester hosts, AST/secret scan, and diff checks.
- [ ] Rewrite the Task 5 report with second-pass RED/GREEN evidence and remaining concerns.
- [ ] Commit the production, test, and tracked documentation changes with a focused message.
