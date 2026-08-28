# Task 8 Second Review Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox syntax for tracking.

**Goal:** Close the second installer security review without live machine mutation.

**Architecture:** Use a two-object signed trust root, CustomActionData-only deferred helpers, first-party sequenced firewall/cleanup actions, and ownership-ledger cleanup. Build and release validate locked tools and publish atomically.

**Tech Stack:** Go 1.27, PowerShell/Pester, WiX v4.0.6, DTF raw-table inspection.

## Global Constraints

- Strict RED then GREEN for every behavior.
- No private key, plaintext credential, live install, or network download.
- Inspect-only artifacts remain unpublishable and fail closed.

### Task 1: Add review-contract RED tests

- [ ] Add Pester/Go assertions for runtime ledger cleanup, CustomActionData, firewall order/rollback, exact trust-root coverage, tool locks, license label, and atomic release publication.
- [ ] Run focused suites and observe expected failures.

### Task 2: Implement lifecycle and MSI sequencing

- [ ] Add exact runtime ownership ledger and idempotent sensitive cleanup.
- [ ] Author type-51 CustomActionData setters and first-party firewall/rollback/cleanup actions.
- [ ] Remove WiX firewall extension authoring and assert raw execution order.
- [ ] Run focused suites GREEN.

### Task 3: Implement artifact trust/build publication

- [ ] Generate metadata before the signed envelope and hash every non-root payload.
- [ ] Enforce Go/WiX/package lock values before staging.
- [ ] Stage release in a unique temporary tree and atomically publish only after inspection.
- [ ] Run failure-path and focused suites GREEN.

### Task 4: Verify and commit

- [ ] Run dual full Pester, Go tests/vet, Windows builds, MSI build/decompile/extract/raw-table inspection.
- [ ] Update `.superpowers/sdd/task-8-report.md` and commit the clean tree.
