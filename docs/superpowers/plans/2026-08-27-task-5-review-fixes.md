# Task 5 Review Fixes Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the Task 5 verdict and Windows no-leak gate fail closed against mixed, stale, malformed, drifted, or executable-substituted evidence.

**Architecture:** Typed versioned artifacts bind inventory, probes, and the continuous down-state monitor to a run ID and normalized configuration digest. The verdict validates identity/time/structure before accepting a pass, compares all captured network state, and separately derives transport reachability from application success. The PowerShell gate trusts only a hash-pinned native probe and monitors the configured telecom path for the entire child-process lifetime.

**Tech Stack:** Portable Go 1.27 standard library, PowerShell 5/7, Pester 3.4.

## Global Constraints

- Do not execute real networking.
- Preserve create-new evidence writes.
- Never read, store, or automate the telecom PIN.
- Test only local fixtures/mocks; do not contact public targets.

---

### Task 1: Versioned configuration-bound artifacts

**Files:**
- Modify: `internal/config/config.go`
- Modify: `internal/config/config_test.go`
- Modify: `internal/inventory/inventory.go`
- Modify: `internal/inventory/windows.go`
- Modify: `internal/inventory/inventory_test.go`
- Modify: `internal/probe/probe.go`
- Modify: `internal/probe/probe_test.go`
- Modify: `configs/poc.example.yaml`

**Interfaces:**
- Produces: `config.Digest(Config) (string, error)` and required `TelecomRoutePrefixes []string`.
- Produces: `inventory.Artifact` with identity, timestamp, interfaces, routes, NAT, and firewall state.
- Produces: `probe.Artifact` with identity, interval, and exact target name/URL results.

- [ ] Add failing tests for required strict `telecom_route_prefixes`, stable configuration digests, NAT/firewall parsing, and target URLs.
- [ ] Run focused Go tests and record the expected RED failures.
- [ ] Implement the minimal typed schemas, collectors, and validation needed by the tests.
- [ ] Run focused Go tests and record GREEN.

### Task 2: Evidence-bound verdict

**Files:**
- Modify: `internal/verdict/verdict.go`
- Modify: `internal/verdict/verdict_test.go`
- Modify: `cmd/poc-probe/main.go`
- Modify: `cmd/poc-probe/main_test.go`

**Interfaces:**
- Consumes: validated config, expected run ID, inventory artifacts, probe artifacts, and down-monitor artifact.
- Produces: report containing status, code, message, run ID, configuration digest, and evaluation timestamp.

- [ ] Add failing tests for exact state drift, unknown JSON fields, empty evidence, freshness, chronology, run/config/target binding, contradictory transport records, and preserved valid leak signals.
- [ ] Run focused Go tests and record the expected RED failures.
- [ ] Implement strict per-record decoding and reachability/health normalization, preserving valid down records when siblings are malformed.
- [ ] Implement evaluation order: bound/fresh down leak, complete evidence validity, monitor reconnect, exact drift, up health, then pass.
- [ ] Run `go test ./... -count=1` and record GREEN.

### Task 3: Continuously monitored native no-leak gate

**Files:**
- Modify: `scripts/windows/assert-no-leak.ps1`
- Modify: `tests/powershell/AssertNoLeak.Tests.ps1`

**Interfaces:**
- Consumes: config path, output paths, run ID, exact `poc-probe.exe` path, and caller-supplied SHA-256.
- Produces: create-new down probe and down-monitor evidence, or explicit reconnect/failure evidence.

- [ ] Add behavioral Pester tests for hash/name rejection, configured route shapes, probe exit failure, finally-based reconnect reminder/failure, and reconnect races.
- [ ] Run Pester 3.4 and record the expected RED failures.
- [ ] Implement pre-disconnect native identity/config checks, process-lifetime monitoring, race-closing sampling, monitor evidence, exit-code handling, and universal reconnect `finally`.
- [ ] Run Pester 3.4 under PowerShell 7 and Windows PowerShell 5 and record GREEN.

### Task 4: Verification and handoff

**Files:**
- Modify: `.superpowers/sdd/task-5-report.md`
- Modify: `.superpowers/sdd/task-5-review-package.md`

**Interfaces:**
- Produces: reviewable RED/GREEN record and one committed Task 5 fix.

- [ ] Run gofmt, full Go tests, build, vet, both Pester hosts, syntax/secret scans, and `git diff --check`.
- [ ] Re-read every requested outcome and record any remaining concern without claiming Task 7 PASS.
- [ ] Update the Task 5 report and review package with the new commit scope and verification evidence.
- [ ] Commit all Task 5 fixes with a focused message.
