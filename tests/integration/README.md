# Windows fail-closed integration gate

This directory contains the version 4 privileged Windows acceptance harness. Ordinary `go test ./...` and `make test-integration-preflight` runs are non-mutating: `TestWindowsFailClosedLifecycle` skips unless every authorization gate is satisfied. Never run the live target on a developer workstation.

Task 10 closes the carried code prerequisites and provides non-live evidence. Elevated execution on a designated disposable physical Windows host remains an external acceptance gate; a repository PASS is not a live PASS.

## Hard refusal gates

Live execution requires all of the following:

1. An elevated Administrator token.
2. `OVERSEAS_ACCESS_INTEGRATION=1`.
3. `OVERSEAS_ACCESS_DISPOSABLE_HOST_ACK=I_ACKNOWLEDGE_THIS_WINDOWS_HOST_IS_DISPOSABLE`.
4. `OVERSEAS_ACCESS_DISPOSABLE_HOST_TOKEN` equal to the current hostname.
5. An existing, empty, absolute, non-reparse `OVERSEAS_ACCESS_BASELINE_DIR`.
6. Exact SHA-256 and approved Authenticode pins for the integration driver and all executable fixture artifacts.
7. Exact pins for the payload, client config, server config, action config, detached-signed fixture manifest, pinned System32 PowerShell, and embedded capture script.
8. Distinct bound identities and endpoints for the public-data/public-health sentinel pair, corporate sentinel, fake control listener, and fake CONNECT/data listener.
9. A detached corporate signature for the release payload manifest, the complete manifest-derived installed-file binding, and the exact signed corporate CIDR/DNS/internal-suffix binding.

The harness creates a new run directory and holds verified handles to the run directory, driver, manifest, artifacts, configs, baseline, and restore inputs. Reparse points, changed identities, stale hashes, trailing JSON, unknown fields, or missing signer allowlists are refused.

Required live variables include:

```powershell
$env:OVERSEAS_ACCESS_INTEGRATION = '1'
$env:OVERSEAS_ACCESS_DISPOSABLE_HOST_ACK = 'I_ACKNOWLEDGE_THIS_WINDOWS_HOST_IS_DISPOSABLE'
$env:OVERSEAS_ACCESS_DISPOSABLE_HOST_TOKEN = $env:COMPUTERNAME
$env:OVERSEAS_ACCESS_BASELINE_DIR = 'C:\integration-evidence\empty-run-directory'
$env:OVERSEAS_ACCESS_INTEGRATION_DRIVER = 'C:\fixture\overseas-access-integration-driver.exe'
$env:OVERSEAS_ACCESS_INTEGRATION_DRIVER_SHA256 = '<sha256>'
$env:OVERSEAS_ACCESS_INTEGRATION_DRIVER_SIGNER = '<approved signer>'
$env:OVERSEAS_ACCESS_PAYLOAD_SHA256 = '<sha256>'
$env:OVERSEAS_ACCESS_GENERATED_CONFIG_SHA256 = '<sha256>'
$env:OVERSEAS_ACCESS_SERVER_CONFIG_SHA256 = '<sha256>'
$env:OVERSEAS_ACCESS_ACTION_CONFIG_SHA256 = '<sha256>'
$env:OVERSEAS_ACCESS_FIXTURE_MANIFEST = 'C:\fixture\fixture-manifest.json'
$env:OVERSEAS_ACCESS_FIXTURE_MANIFEST_SHA256 = '<sha256>'
$env:OVERSEAS_ACCESS_FAKE_UPSTREAM_IDENTITY = 'fake-upstream/run-id'
$env:OVERSEAS_ACCESS_PUBLIC_SENTINEL_IDENTITY = 'public/run-id'
$env:OVERSEAS_ACCESS_CORPORATE_SENTINEL_IDENTITY = 'corporate/run-id'
$env:OVERSEAS_ACCESS_PUBLIC_SENTINEL = '198.18.0.2:18080'
$env:OVERSEAS_ACCESS_PUBLIC_SENTINEL_HEALTH = '172.20.9.251:18080'
$env:OVERSEAS_ACCESS_CORPORATE_SENTINEL = '172.20.9.250:18081'
$env:OVERSEAS_ACCESS_FAKE_UPSTREAM_CONTROL = '172.20.9.15:18082'
$env:OVERSEAS_ACCESS_FAKE_UPSTREAM_DATA = '172.20.9.15:18083'
$env:OVERSEAS_ACCESS_CORPORATE_CIDR = '172.20.8.0/22'
$env:OVERSEAS_ACCESS_FIXTURE_CONFIG = 'C:\fixture\fixture-config.json'
$env:OVERSEAS_ACCESS_FIXTURE_CONFIG_SHA256 = '<sha256>'
```

Addresses are examples only. The fixture must be isolated and must never contact the telecom service or use the production `127.0.0.1:8080` fallback.

## Trusted artifact/configuration model

`make build-integration-fixtures` builds `overseas-access-integration-driver.exe`, `fixture-sentinel.exe`, and `fixture-action.exe`. Staging, ACL protection, detached manifest signing, and Authenticode signing happen only at the authorized live gate.

The strict manifest has one record for each role: `agent`, `core`, `ui`, `server-service`, `driver`, `sentinel`, `action-helper`, `powershell`, `installer`, and `capture-script`. Agent, core, UI, and production server-service records also declare their exact installed paths. The manifest bytes/hash/signature and every artifact are locked and reverified before privileged work. `server-service` always means the production `overseas-server-service.exe`; fake upstream/control/health listeners are separate run-owned roles.

The client config must contain exactly one direct and one tunnel outbound with tunnel final routing. The server config must contain exactly one outbound: tag `fake-connect`, type `http`, exact fake-data endpoint. The locked action config binds the manifest, helper, installer, PowerShell, sentinel, endpoints, identities, and fixed typed operations. Arbitrary command maps are not supported.

The driver, capture PowerShell, and lifecycle helper trees run in kill-on-close Windows Job Objects. Processes are created suspended, assigned before resume, and a timeout does not return until the Job reports zero active processes. Capture uses only the exact manifest-pinned `%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe`; no PATH resolution is allowed. Long-lived fake listeners run through uniquely named, run-owned Windows services supervised by `fixture-action.exe` and return promptly from their start action.

The signed fixture manifest schema additionally requires `corporate_cidrs`, `corporate_dns`, and `internal_suffixes`. The strict action config requires `generated_config_path`, `server_config_path`, `server_config_sha256`, `server_listener_endpoint`, and a future RFC3339 `credential_expires_at`. The release payload manifest must use its emitted schema (`source_commit`, `mode`, signer allowlists, file destination, hashes, and Authenticode requirements); the harness derives every installed file from those signed entries rather than a caller-supplied subset.

The live operator must supply the exact corporate manifest signer allowlist, signed fixture manifest and detached signature, corporate-signed release payload manifest and detached signature, corporate-signed MSI and executable signer allowlists, exact generated client/server/action config hashes, reviewed endpoint/identity values, approved SSH host-key fingerprint, a new empty baseline directory, and the approved disposable physical-host identity/token. None of those external approvals or signatures is fabricated by the repository.

## Version 4 protocol and actions

Each bounded request and response binds protocol version 4, nonce, run ID, scenario, action, evidence-directory identity, baseline hash, every artifact/config hash, every fixture identity, and all five endpoints. Responses are accepted only after action-local capture.

The closed action set is:

- `preflight` and `capture` (read-only);
- `case-setup` (start the locally owned production server, invoke the pinned installer, feed the installed manifest-pinned provisioner through an anonymous pipe derived from the locked client config, start the agent, then independently capture installed state);
- `fake-upstream-start`, `fake-upstream-stop`;
- `core-crash`, `ui-start`, `ui-exit`, `agent-crash`, `agent-start`;
- `stage-machine-recovery`, `machine-recover`;
- `uninstall`, `case-cleanup`, `restore`.

Snapshots contain structured adapters, routes, DNS, services, processes, owned firewall rules, MSI registration, every payload-manifest installed-file hash, unexpected files recursively discovered in both owned roots, owned-root presence, credential/config/runtime-ledger files, registry ownership, recovery/scheduled artifacts, installer transactions, fixture residues, and endpoint listener ownership. Present installed/running roles must match the exact manifest-derived hash. The production server service, service process, child core, exact client-facing listener, and locked runtime config must form one PID/parent/hash chain. Uninstall must prove every payload entry, unexpected file, owned root, and server identity absent before cleanup; cleanup cannot mask an uninstall/restart/recovery failure.

The fake sentinel service owns paired data and health listeners in one failure domain. Listener evidence binds endpoint, unique PID, image path, and exact image hash. Preflight requires exclusive ownership of public data/health and corporate endpoints, while fake control/data endpoints must be free for the later run-owned start action. After start, fake control/data must share one exact sentinel PID parented by the run-owned action-helper service. Successful public probes require a nonce receipt carrying the fake-upstream identity. Failure probes span the reconciliation window with spaced attempts; any data receipt fails immediately while independently owned sentinel health and corporate reachability must remain healthy.

## Current implementation gate

Protocol v4 and the carried Task 10 code prerequisites are implemented and covered by non-live false-pass tests. This means the repository is ready to consume externally signed fixtures; it does not mean the physical-host gate passed. Live acceptance remains blocked until the corporate signer supplies the signed artifacts/config contracts, the operator verifies the SSH host key, and explicit stop/go approval names a disposable physical Windows host.

The code now refuses unrelated private direct routes/DNS servers and suffix text collisions; provisions credentials only through a connected anonymous pipe from a pinned source to the installed manifest-pinned provisioner, with the signed method/endpoint/expiry contract passed to and validated by both processes before agent start; derives setup/uninstall file checks from every signed payload entry and rejects unexpected owned-root files; and requires a fresh run-nonce-bound remote attestation for the exact `DESKTOP-1BVR2H6` server service/config/listener/core PID and hash chain while refusing all local-server residue on the physical client. Integrated tests mutate each binding to prove the corresponding false pass is rejected.

Restoration never consumes the mutable display baseline. Canonical baseline bytes/hash are retained in memory and in an ACL-protected open file; tamper causes a new protected same-run restore input to be created and verified. Cleanup and restore have independent budgets, restore is prioritized, and final canonical state must equal the original baseline exactly. Drift writes evidence and poisons the run.

## External Task 10 procedure

First run read-only preflight on the authorized host:

```powershell
$env:OVERSEAS_ACCESS_INTEGRATION_DRY_RUN = '1'
make test-integration-live
```

After reviewing evidence, obtain stop/go authorization, remove dry-run, use a new empty baseline directory, and run:

```powershell
Remove-Item Env:OVERSEAS_ACCESS_INTEGRATION_DRY_RUN -ErrorAction SilentlyContinue
make test-integration-live
pwsh -NoProfile -Command "& 'scripts/windows/invoke-locked-client-tool.ps1' -Tool Go -ToolArguments @('test','-count=20','./internal/agent','./internal/supervisor'); exit `$LASTEXITCODE"
```

Task 10 must preserve the elevated preflight, complete live scenario matrix, nonce/leak evidence, and exact zero-drift final capture. Until that physical-host run exists, status remains `DONE_WITH_CONCERNS`.
