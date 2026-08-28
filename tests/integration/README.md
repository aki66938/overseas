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
6. The fixture driver is an absolute ordinary, non-reparse `.exe`, with an exact SHA-256 pin and an Authenticode signer allowlist entry. The harness re-verifies it and holds a deny-write/delete handle before every action.
7. The payload and generated client config have exact SHA-256 pins, and the fake upstream and both sentinels have explicit fixture identities.
8. The public data sentinel is outside the corporate CIDR. Its independent health endpoint and the corporate sentinel are distinct endpoints inside the permitted corporate CIDR.

An empty evidence directory is deliberate. It prevents a new run from overwriting or being confused with evidence from an earlier run. The harness creates a timestamped child directory and uses create-new writes for baselines, final snapshots, drift reports, and action records.

Required environment variables:

```powershell
$env:OVERSEAS_ACCESS_INTEGRATION = '1'
$env:OVERSEAS_ACCESS_DISPOSABLE_HOST_ACK = 'I_ACKNOWLEDGE_THIS_WINDOWS_HOST_IS_DISPOSABLE'
$env:OVERSEAS_ACCESS_DISPOSABLE_HOST_TOKEN = $env:COMPUTERNAME
$env:OVERSEAS_ACCESS_BASELINE_DIR = 'C:\integration-evidence\empty-run-directory'
$env:OVERSEAS_ACCESS_INTEGRATION_DRIVER = 'C:\fixture\overseas-access-integration-driver.exe'
$env:OVERSEAS_ACCESS_INTEGRATION_DRIVER_SHA256 = '<64 lowercase hex characters>'
$env:OVERSEAS_ACCESS_INTEGRATION_DRIVER_SIGNER = '<approved Authenticode subject or thumbprint>'
$env:OVERSEAS_ACCESS_PAYLOAD_SHA256 = '<64 lowercase hex characters>'
$env:OVERSEAS_ACCESS_GENERATED_CONFIG_SHA256 = '<64 lowercase hex characters>'
$env:OVERSEAS_ACCESS_FAKE_UPSTREAM_IDENTITY = 'fake-upstream/fixture-2026-08-29'
$env:OVERSEAS_ACCESS_PUBLIC_SENTINEL_IDENTITY = 'public/fixture-2026-08-29'
$env:OVERSEAS_ACCESS_CORPORATE_SENTINEL_IDENTITY = 'corporate/fixture-2026-08-29'
$env:OVERSEAS_ACCESS_PUBLIC_SENTINEL = '198.18.0.2:18080'
$env:OVERSEAS_ACCESS_PUBLIC_SENTINEL_HEALTH = '172.20.9.251:18080'
$env:OVERSEAS_ACCESS_CORPORATE_SENTINEL = '172.20.9.250:18081'
$env:OVERSEAS_ACCESS_FAKE_UPSTREAM_CONTROL = '172.20.9.15:18082'
$env:OVERSEAS_ACCESS_CORPORATE_CIDR = '172.20.8.0/22'
$env:OVERSEAS_ACCESS_FIXTURE_CONFIG = 'C:\fixture\fixture-config.json'
$env:OVERSEAS_ACCESS_FIXTURE_CONFIG_SHA256 = '<64 lowercase hex characters>'
```

The addresses above are examples only. The operator must use endpoints on the isolated fixture that are reachable before setup. The public sentinel represents a local ordinary-gateway path and must not contact the Internet or the telecom service. The public health listener is a second listener owned by that same sentinel identity on the always-permitted fixture network; it proves that a blocked data probe is not a dead-listener false pass.

Build the versioned fixture binaries with `make build-integration-fixtures`. They must then be staged on the disposable host under Administrator/SYSTEM ownership, ACL-protected, and signed according to the site policy. Building them does not authorize running them.

`OVERSEAS_ACCESS_FIXTURE_CONFIG` is strict JSON schema version 1 and is independently pinned by `OVERSEAS_ACCESS_FIXTURE_CONFIG_SHA256`; the harness holds a deny-write/delete handle while each action runs. It supplies `host_identity`, the authorized empty evidence `evidence_root`, absolute `payload_path` and `generated_config_path`, the same `binding` hashes/identities listed above, `public_sentinel`, `public_sentinel_health`, `corporate_sentinel`, `fake_upstream_control`, and `commands`, `command_sha256`, and `command_signers` objects. Every mutating version-2 action listed below must map to exactly one absolute `.exe` command plus an exact hash and nonempty Authenticode allowlist. The driver re-verifies and deny-write locks that command before every action, starts it suspended, assigns it to a kill-on-close Job Object, resumes it, and waits for the complete process tree to quiesce. Missing, relative, unsigned, changed, escaped-child, or extra actions are refused. Persistent fixture processes must be managed by an ownership-proven Windows service or equivalent supervisor rather than an escaping child. Preflight and capture are built into the driver and cannot be replaced by config commands.

The official `fixture-sentinel.exe -mode sentinel` requires both `-listen` and `-health-listen` and owns the pair in one process/failure domain. Loss of either listener terminates both, preventing a dead data listener from being hidden by a separately healthy process. The corporate sentinel may use its paired health listener even though only its data endpoint is consumed by this matrix.

## Read-only driver preflight

After all hard gates are populated, add this variable and invoke the live target:

```powershell
$env:OVERSEAS_ACCESS_INTEGRATION_DRY_RUN = '1'
make test-integration-live
```

Dry-run mode performs the harness gates and calls only the driver's `preflight` action. That action must be read-only. Inspect the new evidence directory, remove the dry-run variable, create a new empty baseline directory, and obtain the Task 10 stop/go approval before live execution.

## Fixture-driver protocol

The repository contains the Task 10/authorized-host adapter at `tests/integration/fixturedriver` and the sentinel/fake-CONNECT service at `tests/integration/fixtureserver`. The signed driver reads exactly one bounded JSON request from standard input and emits exactly one response. It never invokes a shell: every mutating action must map to an absolute executable plus fixed arguments in the versioned fixture config. Secret material must never appear in arguments, stdout, stderr, or evidence.

Request version 2:

```json
{
  "protocol_version": 2,
  "request_nonce": "fresh-cryptographic-nonce",
  "run_id": "run-20260829T...",
  "action": "capture",
  "scenario": "core-exits",
  "evidence_directory": "C:\\integration-evidence\\...",
  "evidence_directory_identity": "volume:01234567/file:89abcdef01234567",
  "baseline_path": "C:\\integration-evidence\\...\\.trusted-baseline-....json",
  "baseline_sha256": "<64 lowercase hex characters>"
}
```

Every response repeats the protocol version, fresh nonce, run ID, scenario, and action. It also binds the payload/config hashes, fake-upstream identity/control endpoint, and both sentinel identities plus the exact public-data, public-health, and corporate endpoints. `evidence` contains an action-specific post-state hash and required residue facts; `snapshot` contains nonempty structured adapter, route, DNS, service, process, and owned-firewall captures. Empty arrays, stale observation nonces, unknown fields, missing process roles, trivial records, mismatched hashes, and trailing output are refused.

The driver independently recomputes the payload/config hashes and the actual run-directory file identity before every command. For every mutating action it also verifies that the held baseline input is inside the current run directory and matches `baseline_sha256`. The harness independently performs the same run-directory check, verifies the driver's pinned hash/signature, and holds a deny-write/delete driver handle for the complete action. Restoration never reads the mutable display copy `baseline.json`; if that copy is changed, the harness recreates a new ACL-protected restore input from the canonical bytes retained in memory and in an already-open immutable file.

An abbreviated success envelope is:

```json
{"protocol_version":2,"request_nonce":"...","run_id":"...","scenario":"core-exits","action":"capture","ok":true,"binding":{"payload_sha256":"...","config_sha256":"...","fake_upstream_identity":"...","public_sentinel_identity":"...","corporate_sentinel_identity":"..."},"evidence":{"kind":"capture","observation_nonce":"...","facts":{"host_identity":"...","snapshot_sha256":"...","post_state_sha256":"..."}},"snapshot":{"observation_nonce":"...","adapters":[{}],"routes":[{}],"dns":[{}],"services":[{}],"processes":[{}],"owned_firewall_rules":[{}]}}
```

The canonical state comparison sorts every collection, omits only the observation nonce, and preserves identity-defining fields. Capturing only counts is not acceptable. Version-2 actions are:

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

The matrix covers connection through the fake upstream, upstream absent, upstream death, core exit, UI exit, agent service restart, machine-style recovery, 20 connect/disconnect cycles, and uninstall cleanup. Each unavailable-tunnel failure makes spaced, nonce-bearing attempts for the complete reconciliation window and fails immediately on any public data receipt. Every failed data attempt is paired with a nonce/identity receipt from the public sentinel's independent health listener and the corporate sentinel. A success is accepted only when the public sentinel returns the same nonce plus the expected fake-upstream traversal identity; a direct receipt is a failure.

Before every case the harness writes the exact baseline and retains trusted custody. Uninstall, restart, and recovery actions synchronously capture their exact post-state and action-specific residue facts before case cleanup can run. A deferred cleanup and restore always runs even after an assertion failure; cleanup and restore have fresh independent deadlines, and restore still runs after a hung cleanup. The harness then recaptures state and compares it exactly. A mismatch writes `STATE-DRIFT.json`, poisons the run, and prevents later cases. `TestMain` performs a final trusted-byte cleanup/restore attempt if a case exits before restoration was proven. Failure evidence must not be deleted or reused.

The required external GREEN evidence is:

```powershell
make test-integration-live
pwsh -NoProfile -Command "& 'scripts/windows/invoke-locked-client-tool.ps1' -Tool Go -ToolArguments @('test','-count=20','./internal/agent','./internal/supervisor'); exit `$LASTEXITCODE"
```

A non-live repository PASS is not a substitute for this physical-host gate.
