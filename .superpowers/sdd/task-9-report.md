# Task 9 Report — Windows Fail-Closed Integration Harness v3

## Status

`BLOCKED`: the protocol-v3 safety harness and its non-live false-pass defenses are substantially implemented and verified, but adversarial review found four code prerequisites that make the clean-host live lifecycle incomplete. Task 9 therefore does not claim code-complete or live PASS. The remaining implementation and physical-host acceptance are explicitly tracked in `task-10-brief.md`.

This workstation is not designated disposable. `OVERSEAS_ACCESS_INTEGRATION=1` was never set, and no route, DNS, adapter, firewall, service, installer, credential, or runtime mutation was performed.

## Current implementation

- Protocol version 3 binds payload/client/server/action config hashes; exact agent, core, UI, production server-service, driver, sentinel, action-helper, System32 PowerShell, installer, capture-script, and manifest hashes; all fixture identities; and public-data/public-health/corporate/fake-control/fake-data endpoints.
- The fixture manifest, detached signature, configs, driver, helper, capture runtime, and declared artifacts are path/hash/signature checked and held with deny-write/delete semantics around privileged work. Run/case directory handles are reparse-checked after open.
- Client/server configs are strict JSON and cross-bind the client tunnel to the server inbound and the server outbound to the fake CONNECT/data listener. Telecom/`127.0.0.1:8080`, extra fallback outbounds, unknown network-bearing top-level surfaces, remote rule sets, and unreviewed route actions are refused.
- The harness, driver capture, and typed helper execute through suspended-create/assign-before-resume kill-on-close Jobs. The shared runner waits for zero active processes. Live driver timeouts join the quiescence path before cleanup/restore can begin.
- `fixture-action.exe` exposes only the 13 reviewed actions. Installer operations use fixed arguments; persistent fake/UI children are supervised by unique run-owned Windows services. Start actions wait for listener/child readiness.
- Fake control/data listeners must share one exact sentinel PID whose parent is the expected run-owned action-helper service PID. Public data/health must share one sentinel PID. Preflight requires fake endpoints free; the later start action proves ownership.
- Snapshot v3 covers structured adapters, routes, DNS, services, processes, firewall, MSI, installed/runtime files, registry, ownership, recovery, transaction, fixture residue, and listener surfaces. Present known roles require exact bound hashes; canonical comparison excludes only transient PIDs/nonces.
- Baseline custody retains canonical bytes/hash in memory and an ACL-protected open file. A changed display baseline causes a new same-run protected restore input. Cleanup and restore use independent budgets, and exact final drift is always checked.
- Leak failures span the reconciliation window with spaced attempts, fail on any data receipt, and independently require the paired health/corporate sentinels to remain healthy. Success requires a nonce receipt carrying the fake-upstream identity.

## Strict RED → GREEN evidence

Review fixes were each driven by focused failing tests before implementation, including:

- missing artifact/config/endpoint bindings and wrong present image hashes;
- direct public route, unreviewed DNS, remote rule-set, and client/server inbound mismatches;
- split fake listener PIDs and missing run-owned supervisor linkage;
- preflight requiring already-running fake endpoints, which contradicted run-owned start;
- absent recovery staging evidence and mismatched marker/capture locations;
- vacuous installed-hash facts and missing agent/server-service uninstall facts;
- action helper output not bound to request identity and Jobs returning before quiescence;
- driver timeout returning before the live quiescence join completed;
- installed runtime config hash mismatch and Connect-time installed executable swaps.

All implemented review tests are green in the non-live suite.

## Unresolved code prerequisites

1. Clean-host `case-setup` invokes the real client installer, but the installer intentionally leaves the agent stopped without `credential.bin`. The typed helper does not yet invoke the installed, payload-manifest-pinned credential provisioner with pipe-only fixture input, so its required running-service postcondition cannot be achieved.
2. Snapshot/setup/uninstall coverage does not yet derive every installed file from the signed client payload manifest. Provisioner/verifier/Wintun/library/metadata files and unexpected owned-root residue could be omitted from immediate evidence.
3. The client direct-route/DNS checks currently constrain targets to private ranges but do not bind them to an explicit signed corporate CIDR/DNS/suffix allowlist. An unrelated private target can pass.
4. The production server service/config and client-facing Shadowsocks listener are hash-bound as artifacts/config bytes but are not yet lifecycle-controlled or locally/remotely attested as the process that handled the tested connection.

These are live false-pass/blocking conditions, not physical-host-only observations. They must be implemented and reviewed before enabling the live gate.

## Non-live verification

The implementation was checked without live opt-in using:

- focused `go test -count=1 ./tests/integration/...` during each RED/GREEN slice;
- `go test -count=20 ./tests/integration/fixtureproto ./tests/integration/fixtureconfig ./internal/agent ./internal/supervisor`;
- `go test -count=1 ./...`;
- `go vet ./...`;
- Windows amd64 builds of driver, sentinel, action helper, agent, UI, credential provisioner, installer verifier, and production server service through the locked Go wrapper;
- Windows PowerShell 5.1 Pester and PowerShell 7 Pester: `108 passed, 0 failed` in each runtime;
- `git diff --check` (only configured LF→CRLF warnings).

The final matrix was rerun after the last review batch before commit; exact results are recorded in the handoff message.

## Commit/design lineage

- `2b503d3` — first review hardening: trusted baseline custody, timeout/TOCTOU/leak fixes, versioned fixture protocol.
- `f00608e` — accepted Task 9 second-review design.
- `c13d65c` — detailed TDD implementation plan.
- The implementation/report commit following those documents contains protocol v3, the typed helper, Job runner, expanded evidence, tests, this blocked report, and the Task 10 prerequisite ledger.

## External gate

After the four code prerequisites are green, Task 10 must stage signed/ACL-protected artifacts on the authorized disposable physical Windows host, run elevated dry-run/preflight, obtain stop/go approval, execute all nine scenarios plus 20 repetitions, and preserve nonce/leak and exact zero-drift evidence. Until then, neither Task 9 nor Task 10 may claim live acceptance.

## Cross-platform Task 9 — Linux implementation, 2026-09-07

This section concerns current task-9-brief.md; preceding sections describe historical Windows work and remain intact. Review base: `32123ac4131aaec46504256c49d999ca13fe0837`. Linux native and distribution gates remain pending.

### Slice 1: portable CLI and API v1 dispatch

- Added fixed connect/disconnect/status/probe commands using the existing v1 client, bounded action deadlines, concise state/quality/duration/target latency output and exit codes 0 success, 1 operation failure, 2 usage. Existing administrator diagnostic syntax retained; raw client error details are not printed.
- Extracted LocalHandler from Windows v1 processing, retaining authenticated peer authority at the transport. Windows named-pipe authentication and legacy dispatch unchanged.
- RED: Go 1.27.0 `test ./cmd/regen-access -run 'TestCommandsGolden|TestCommandFailureGolden' -count=1` failed: all new commands returned usage/2. GREEN: `test ./cmd/regen-access -count=1` passed after implementation.
- RED: `test ./cmd/regen-access -run TestStatusDurationAndProbeGolden -count=1` failed: duration/probes absent. GREEN: package passed after implementation; deterministic clock used in golden.
- RED: `test ./internal/agent -run TestLocalDispatchAuthorizationAndProjection -count=1` failed because NewLocalHandler did not exist. GREEN: `test ./internal/agent -run 'TestLocalDispatch|TestPipe' -count=1` passed.
- Full Windows `test ./... -count=1`: all packages except existing internal/supervisor passed. `TestReadyTimeoutReturnsBoundedRedactedCoreTail` did not capture final stderr warning before its short deadline; no supervisor production code changed. Focused repetition recorded below. This full run is not claimed green.
- No network/service/remote operations performed. Next slices: native socket, process ownership, trust, journal and network transaction implementation with parent-coordinated VM116 tests.
- Focused `test ./internal/supervisor -run TestReadyTimeoutReturnsBoundedRedactedCoreTail -count=5` passed all five; this supports a timing-sensitive failure without erasing the full-run result.
