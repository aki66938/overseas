# Task 9 Report — Windows Fail-Closed Integration Harness

## Status

`DONE_WITH_CONCERNS`: the privileged harness, safety gates, lifecycle matrix, evidence contract, and non-live verification are implemented. The required live RED/GREEN run was intentionally not executed because this development workstation is not the designated disposable physical Windows test host. That physical-host gate remains for Task 10.

No route, DNS, adapter, firewall, service, installer, or real tunnel mutation was performed. `OVERSEAS_ACCESS_INTEGRATION=1` was never set during this task.

## Implemented contract

- Live execution requires all four independent authorization boundaries: elevated Administrator token, exact integration opt-in, exact disposable-host acknowledgement plus a hostname-bound token, and an existing empty absolute non-reparse evidence directory.
- The Task 10 fixture driver is also required to be an absolute ordinary non-reparse file. Public/corporate TCP sentinels must be distinct non-loopback IPv4 endpoints, with the corporate endpoint inside the declared corporate CIDR and the ordinary-gateway endpoint outside it.
- The driver uses a versioned one-request/one-response JSON stdin/stdout protocol. It owns signed-payload setup, the isolated fake upstream, crash/restart/recovery injection, transactional uninstall, cleanup, and exact host restoration. Driver output is not echoed on failure, preventing accidental evidence/log disclosure.
- The test covers success through the fake upstream, upstream absent, upstream death, core exit, UI exit, agent crash/restart, machine-style recovery, 20 connect/disconnect cycles, and uninstall cleanup.
- Unavailable-tunnel cases make three independent public TCP attempts and fail on any successful ordinary-gateway connection; the corporate sentinel must remain reachable. The upstream-absent/death assertions correctly accept either a locally ready core or a failed core because local TUN readiness does not prove remote upstream health.
- Before every case the harness captures canonical routes, DNS, adapters, services, processes, and complete owned-firewall state. Baselines use create-new durable writes, are checked against modification, and are compared exactly to a final canonical snapshot.
- Deferred cleanup/restore runs after every case. State drift poisons the run and stops later cases. `TestMain` retains a last-chance cleanup/restore/capture comparison whenever restoration is unproven.
- `test-integration-preflight` forcibly clears the opt-in and executes the non-live package. `test-integration-live` refuses unless the operator already set the exact opt-in; it does not silently enable mutation.

## Strict TDD evidence

- Initial RED: the integration package failed to compile on missing preflight and scenario-plan APIs.
- Documentation/target RED: the repository contract test failed because `tests/integration/README.md` and Make targets did not exist.
- Lifecycle-semantics RED: the unavailable-upstream test failed before the state predicate existed; implementation then stopped requiring an impossible remote-health transition from the local controller.
- Recovery-hook RED: the last-chance-release test failed before the harness proved that no active/poisoned restoration remained.
- Evidence-integrity RED: the preserved-baseline test failed before baseline modification detection existed.
- Disclosure RED: a local fake driver wrote a secret marker to stderr and the test proved it appeared in the error before driver output was suppressed.
- Snapshot-schema RED: a `null` route surface was accepted before strict array validation was added.

All RED cases were observed for the expected missing/incorrect behavior before their minimal GREEN implementation.

## Fresh non-live verification

- Integration guard/package suite: PASS; 11 tests passed and the single privileged lifecycle test skipped because opt-in was absent.
- `go test -count=20 ./internal/agent ./internal/supervisor`: PASS for both packages.
- `go test -count=1 ./...`: PASS for all packages.
- `go vet ./...`: exit 0.
- Windows amd64 agent, GUI client, credential provisioner, and installer verifier builds: exit 0 through the locked Go wrapper.
- Windows PowerShell 5.1 Pester: `108 passed, 0 failed`.
- PowerShell 7 Pester: `108 passed, 0 failed`.
- `git diff --check`: clean apart from the repository's configured LF-to-CRLF warning.
- GNU Make was not installed, so the tracked target bodies were validated by contract tests and their exact locked-Go command equivalents were executed directly.

## External Task 10 gate

The following evidence does not exist yet and must not be inferred from the non-live PASS:

1. Corporate-signed client payload and generated disposable-host configs.
2. Authorized fixture driver controlling the fake upstream and both local sentinels without contacting the telecom service.
3. Elevated dry-run/preflight evidence on the designated physical host.
4. Live RED evidence while integration hooks are deliberately incomplete, followed by live GREEN for all nine scenarios.
5. Exact zero-drift baseline/final evidence from the physical host.

Until that gate is run, Task 9 is implementation-complete but live acceptance remains blocked.
