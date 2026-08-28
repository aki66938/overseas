# Windows fail-closed integration gate

This directory contains the privileged, opt-in acceptance harness for the Windows tunnel lifecycle. The default Go test run is non-mutating: the live test skips unless every authorization gate is satisfied. The live matrix must not be run on a developer workstation.

Live execution is an external Task 10 gate. It requires an elevated shell on a designated disposable physical Windows host, a corporate-signed client payload, a prepared isolated fixture, and operator approval. Task 9 development intentionally does not claim a live PASS.

## Non-live verification

`make test-integration-preflight` runs only the guard, scenario-plan, snapshot-schema, and documentation tests. It clears the live opt-in for that child process and does not call the fixture driver or mutate routes, DNS, adapters, services, processes, or firewall state.

The ordinary `go test ./...` path behaves the same way: `TestWindowsFailClosedLifecycle` is skipped when `OVERSEAS_ACCESS_INTEGRATION` is unset.

## Hard authorization gates

The live test refuses to start unless all of the following are true:

1. The shell has an elevated Administrator token.
2. `OVERSEAS_ACCESS_INTEGRATION` is exactly `1`.
3. `OVERSEAS_ACCESS_DISPOSABLE_HOST_ACK` is exactly `I_ACKNOWLEDGE_THIS_WINDOWS_HOST_IS_DISPOSABLE`.
4. `OVERSEAS_ACCESS_DISPOSABLE_HOST_TOKEN` equals the current Windows hostname (case-insensitive).
5. `OVERSEAS_ACCESS_BASELINE_DIR` is an existing, empty, absolute directory and is not a symlink or reparse point.
6. The fixture driver is an absolute ordinary, non-reparse file.
7. Both TCP sentinels are distinct non-loopback IPv4 endpoints; the corporate sentinel is inside the declared corporate CIDR and the public sentinel is outside it.

An empty evidence directory is deliberate. It prevents a new run from overwriting or being confused with evidence from an earlier run. The harness creates a timestamped child directory and uses create-new writes for baselines, final snapshots, drift reports, and action records.

Required environment variables:

```powershell
$env:OVERSEAS_ACCESS_INTEGRATION = '1'
$env:OVERSEAS_ACCESS_DISPOSABLE_HOST_ACK = 'I_ACKNOWLEDGE_THIS_WINDOWS_HOST_IS_DISPOSABLE'
$env:OVERSEAS_ACCESS_DISPOSABLE_HOST_TOKEN = $env:COMPUTERNAME
$env:OVERSEAS_ACCESS_BASELINE_DIR = 'C:\integration-evidence\empty-run-directory'
$env:OVERSEAS_ACCESS_INTEGRATION_DRIVER = 'C:\fixture\overseas-access-integration-driver.ps1'
$env:OVERSEAS_ACCESS_PUBLIC_SENTINEL = '198.18.0.2:18080'
$env:OVERSEAS_ACCESS_CORPORATE_SENTINEL = '172.20.9.250:18081'
$env:OVERSEAS_ACCESS_CORPORATE_CIDR = '172.20.8.0/22'
```

The addresses above are examples only. The operator must use endpoints on the isolated fixture that are reachable before setup. The public sentinel represents a local ordinary-gateway path and must not contact the Internet or the telecom service. The corporate sentinel represents a permitted corporate-CIDR path.

## Read-only driver preflight

After all hard gates are populated, add this variable and invoke the live target:

```powershell
$env:OVERSEAS_ACCESS_INTEGRATION_DRY_RUN = '1'
make test-integration-live
```

Dry-run mode performs the harness gates and calls only the driver's `preflight` action. That action must be read-only. Inspect the new evidence directory, remove the dry-run variable, create a new empty baseline directory, and obtain the Task 10 stop/go approval before live execution.

## Fixture-driver protocol

The driver is the Task 10/authorized-host adapter. A `.ps1` driver is launched with `pwsh.exe -NoProfile -NonInteractive -File`; another extension is launched directly. Each invocation reads exactly one JSON request from standard input and returns exactly one JSON response on standard output. Secret material must never appear in arguments, stdout, stderr, or evidence.

Request version 1:

```json
{
  "protocol_version": 1,
  "action": "capture",
  "scenario": "core-exits",
  "evidence_directory": "C:\\integration-evidence\\...",
  "baseline_path": "C:\\integration-evidence\\...\\baseline.json"
}
```

Success response:

```json
{"protocol_version":1,"ok":true,"message":"sanitized operator note"}
```

`capture` additionally returns a canonical snapshot:

```json
{
  "protocol_version": 1,
  "ok": true,
  "snapshot": {
    "routes": [],
    "dns": [],
    "adapters": [],
    "services": [],
    "processes": [],
    "owned_firewall_rules": []
  }
}
```

The driver must sort every collection, omit timestamps/counters and its own transient process, and preserve identity-defining fields. The two captures must therefore be byte-equivalent after JSON canonicalization. `services` and `processes` must include the owned agent, UI, core, fake upstream, and any fixture service/process whose residue would invalidate restoration. `owned_firewall_rules` must include both installer-owned and runtime-owned names with their complete effective filters. Capturing only counts is not acceptable.

Version-1 actions are:

- `preflight`: read-only verification of signed payloads, generated configs, fake-upstream controls, sentinels, and rollback ability.
- `capture`: capture routes, DNS, adapters, services, processes, and owned firewall rules.
- `case-setup`: install/reset the signed client and generated test configuration from the recorded clean baseline.
- `fake-upstream-start` / `fake-upstream-stop`: control the isolated fake upstream; it replaces `127.0.0.1:8080` on the server fixture and must never fall through to the telecom proxy.
- `core-crash`: terminate the current owned core generation without a graceful disconnect.
- `ui-start` / `ui-exit`: launch and close only the owned desktop client.
- `agent-crash` / `agent-start`: terminate the SCM process without cleanup, then start the service so startup reconciliation runs.
- `stage-machine-recovery` / `machine-recover`: create an ownership-proven interrupted-machine residue and invoke the same machine-context recovery path used after reboot.
- `uninstall`: invoke the transactional uninstall and prove owned residue is absent.
- `case-cleanup`: idempotently stop test processes and request controlled cleanup.
- `restore`: idempotently restore the referenced baseline. Refusal or uncertainty must return `ok:false` and leave evidence intact.

The fake upstream and both sentinel listeners belong to the isolated fixture. The driver must bind them only to the documented test addresses, verify listener ownership before reporting success, and stop them during `case-cleanup`/`restore`.

## Live matrix and assertions

With dry-run removed and a fresh empty evidence directory:

```powershell
Remove-Item Env:OVERSEAS_ACCESS_INTEGRATION_DRY_RUN -ErrorAction SilentlyContinue
make test-integration-live
```

The matrix covers connection through the fake upstream, upstream absent, upstream death, core exit, UI exit, agent service restart, machine-style recovery, 20 connect/disconnect cycles, and uninstall cleanup. Each unavailable-tunnel failure makes three independent TCP attempts to the ordinary-gateway sentinel and fails immediately on any successful connection; the corporate sentinel must remain reachable. Success/UI cases prove both paths reachable as intended.

Before every case the harness writes the exact baseline. A deferred cleanup and restore always runs, even after an assertion failure, then recaptures state and compares it exactly. A mismatch writes `STATE-DRIFT.json`, poisons the run, and prevents later cases. `TestMain` performs a final cleanup/restore attempt if a case exits before restoration was proven. Failure evidence must not be deleted or reused.

The required external GREEN evidence is:

```powershell
make test-integration-live
pwsh -NoProfile -Command "& 'scripts/windows/invoke-locked-client-tool.ps1' -Tool Go -ToolArguments @('test','-count=20','./internal/agent','./internal/supervisor'); exit `$LASTEXITCODE"
```

A non-live repository PASS is not a substitute for this physical-host gate.
