# Task 9 Second-Review Hardening Implementation Plan

> **Execution requirement:** follow strict RED -> GREEN for each slice. Never set `OVERSEAS_ACCESS_INTEGRATION=1` or invoke the live lifecycle test on this workstation.

**Goal:** Upgrade the Windows integration fixture to protocol v3 with manifest-derived exact artifact identity, semantic fake-upstream isolation, complete process-tree containment, an in-repo typed lifecycle helper, and exact expanded post-state/residue evidence.

**Architecture:** The harness locks and launches the driver in a kill-on-close Job. The driver locks a signed artifact manifest/config/input set, semantically validates client/server configuration, and launches capture/helper/installer trees in nested Jobs. A single native `fixture-action.exe` implements the thirteen typed lifecycle actions and independently verifies their post-state. Long-lived fake listeners are run-owned Windows services. Protocol v3 binds every artifact hash and relevant endpoint and validates expanded snapshots against those bindings.

**Tech stack:** Go 1.25, `golang.org/x/sys/windows`, Windows service APIs, strict JSON, existing PowerShell installer/Pester suites, Make.

---

## Task 1: Protocol v3 artifact and state contract

**Files:**
- Modify: `tests/integration/fixtureproto/protocol.go`
- Modify: `tests/integration/fixtureproto/protocol_test.go`
- Modify: `tests/integration/hardening_windows_test.go`

1. Add failing table tests for omitted/mismatched manifest, agent, core, UI, server-service, driver, sentinel, action-helper, PowerShell, installer, and capture-script hashes; add a failing fake CONNECT/data endpoint test.
2. Add failing snapshot tests for wrong present process/service/file hashes and for missing MSI, installed-file, credential/config, registry, runtime-ledger, recovery/scheduled, transaction, fixture-residue, and listener surfaces.
3. Run `go test -count=1 ./tests/integration/fixtureproto` and record the expected compile/assertion failures.
4. Advance `ProtocolVersion` to 3, add an `ArtifactBinding`, fake-data endpoint, expanded record types, and binding-aware `ValidateResponse`/`Snapshot.Validate`.
5. Canonicalize every new state surface deterministically while excluding ephemeral PIDs only.
6. Run the focused package tests to GREEN.

## Task 2: Signed manifest and configuration semantics

**Files:**
- Create: `tests/integration/fixtureconfig/config.go`
- Create: `tests/integration/fixtureconfig/config_test.go`
- Modify: `tests/integration/fixturedriver/main_windows.go`
- Modify: `tests/integration/fixturedriver/main_windows_test.go`
- Modify: `tests/integration/failclosed_windows_test.go`

1. Write failing tests for an unbound/changed manifest, arbitrary duplicate hashes, telecom or `127.0.0.1:8080` upstreams, fallback/extra upstreams, mismatched fake data endpoint, and ambiguous listener ownership.
2. Run focused integration tests and record RED.
3. Implement strict manifest parsing with role-to-path/hash records and required role set. Lock manifest plus all relevant artifacts; derive response binding from it.
4. Implement shared strict client/server config semantic parsing. Require exactly one outbound upstream equal to the bound fake CONNECT/data endpoint and reject prohibited/extra targets.
5. Add a listener-ownership abstraction and native Windows implementation binding endpoint -> single PID -> run-owned service -> expected image hash.
6. Revalidate manifest/config/listeners before every mutation and Connect-dependent action; run focused tests GREEN.

## Task 3: Complete Job containment and pinned capture runtime

**Files:**
- Create: `tests/integration/winjob/job_windows.go`
- Create: `tests/integration/winjob/job_windows_test.go`
- Modify: `tests/integration/failclosed_windows_test.go`
- Modify: `tests/integration/hardening_windows_test.go`
- Modify: `tests/integration/fixturedriver/main_windows.go`
- Modify: `tests/integration/fixturedriver/main_windows_test.go`

1. Write failing descendant-process tests proving outer driver/capture/helper children cannot outlive timeout and that restore waits for quiescence.
2. Write failing tests proving PATH-resolved or hash-mismatched PowerShell is rejected.
3. Implement reusable suspended-create, assign-before-resume, kill-on-close Job execution with bounded termination and active-process-zero wait.
4. Replace harness `exec.CommandContext` driver launch with Job execution. Use the same primitive for driver capture and helper execution.
5. Resolve PowerShell only from the exact System32 path, verify its manifest-bound SHA-256 before launch, and pass capture without shell/PATH resolution.
6. Run focused tests GREEN.

## Task 4: In-repo typed lifecycle action helper

**Files:**
- Create: `tests/integration/fixtureaction/main_windows.go`
- Create: `tests/integration/fixtureaction/main_windows_test.go`
- Create: `tests/integration/fixtureaction/main_stub.go`
- Modify: `tests/integration/fixturedriver/main_windows.go`
- Modify: `tests/integration/fixturedriver/main_windows_test.go`

1. Add failing tests enumerating exactly all thirteen actions, rejecting unknown/free-form commands, and checking fixed installer/MSI argument templates.
2. Add failing dependency-driven lifecycle tests for install/reset, fake service start/stop, core/UI/service crash/restart/recovery, machine recovery staging, transactional uninstall, cleanup, and trusted restore.
3. Add failing tests that each action captures and validates its own post-state before returning and that cleanup cannot satisfy an earlier action.
4. Implement strict request/config types and a closed action dispatch table. Use direct Windows service/process/registry APIs where practical and invoke only manifest-pinned installer/MSI operations for product install/repair/uninstall.
5. Implement run-owned service installation/control for persistent fake data/control/health listeners, with unique service names and ownership marker.
6. Return structured action results/facts to the driver; remove arbitrary per-action command maps.
7. Run focused helper/driver tests GREEN.

## Task 5: Expanded native/PowerShell state capture and exact assertions

**Files:**
- Modify: `tests/integration/fixturedriver/main_windows.go`
- Modify: `tests/integration/fixturedriver/main_windows_test.go`
- Modify: `tests/integration/fixtureproto/protocol.go`
- Modify: `tests/integration/failclosed_windows_test.go`

1. Add failing false-pass tests for wrong installed/running hashes, stale MSI registration, credential/config/registry/ledger/scheduled/transaction residue, fixture residue, and uninstall evidence captured only after cleanup.
2. Extend pinned capture to return all protocol v3 surfaces, using exact hashes and no secret contents.
3. Validate role hashes against the manifest-derived binding for every relevant installed/running state.
4. Strengthen action-specific required facts. Require uninstall absence across every product surface before cleanup; require fake service/listener facts for start/stop; require exact role hashes for restart/recovery.
5. Run focused tests GREEN, including repeated false-pass tests.

## Task 6: Harness v3 wiring, documentation, and build contract

**Files:**
- Modify: `tests/integration/failclosed_windows_test.go`
- Modify: `tests/integration/hardening_windows_test.go`
- Modify: `tests/integration/README.md`
- Modify: `Makefile`
- Modify: `.superpowers/sdd/task-9-report.md`

1. Add failing contract tests for the new manifest/config/environment gates, fixture-action build target, exact System PowerShell pin, fake-data endpoint, and v3 documentation.
2. Wire environment parsing to the new locked manifest and endpoint fields; build the expected binding from trusted manifest content.
3. Update `build-integration-fixtures` to build driver, sentinel, and lifecycle helper.
4. Rewrite the README and Task 9 report for v3/current commit history, action dependencies, non-live evidence, and explicit Task 10 live acceptance.
5. Run integration package tests GREEN with the live opt-in absent.

## Task 7: Full non-live verification and review

1. Ensure `OVERSEAS_ACCESS_INTEGRATION` is absent and run `go test -count=1 ./tests/integration/...`.
2. Run `go test -count=20 ./tests/integration/fixtureproto ./tests/integration/fixtureconfig` and targeted agent/supervisor repetitions.
3. Run `go test -count=1 ./...` and `go vet ./...`.
4. Cross-build Windows amd64 driver, sentinel, fixture action helper, agent, UI, credential provisioner, installer verifier, and server service through the locked Go wrapper.
5. Run Windows PowerShell 5.1 Pester and PowerShell 7 Pester.
6. Run `git diff --check`, inspect the complete diff for safety/TOCTOU/false-pass gaps, and request code review.
7. Fix review findings with new RED tests before code changes, rerun the affected focused tests, then rerun the complete non-live gate.
8. Commit implementation and rewritten report. Report `DONE_WITH_CONCERNS`: code/non-live complete, live physical-host acceptance externally gated; never claim live PASS.

